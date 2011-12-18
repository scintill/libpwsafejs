function PWSafeDB(data) {
    this._view = new jDataView(data);
}

jQuery.extend(PWSafeDB.prototype, {

BLOCK_SIZE: 16,

validate: function() {
    if (this._getString(this._view, 4) != "PWS3") {
        throw "Not a PWS v3 file";
    }

    this._eofMarkerPos = this._view.byteLength - 32 - this.BLOCK_SIZE;

    var eofMarker = null;
    if (this._eofMarkerPos > 0) {
        eofMarker = this._getString(this._view, this.BLOCK_SIZE, this._eofMarkerPos);
    }

    if (eofMarker != "PWS3-EOFPWS3-EOF") {
        throw "No EOF marker found - not a valid v3 file, or it's corrupted";
    }

    return true;
},

decrypt: function(key) {
    this.validate();

    var salt = this._getString(this._view, 32, 4);
    var iter = this._view.getUint32();
    var expectedStretchedKeyHash = this._getHexStringFromBytes(this._view, 32);
    var stretchedKey = this._stretchKeySHA256(key, salt, iter);
    var stretchedKeyHash = Crypto.SHA256(stretchedKey);

    if (expectedStretchedKeyHash !== stretchedKeyHash) {
        throw "Incorrect password";
    }

    var keyView = this._dataViewFromPlaintext(TwoFish.decrypt(this._view, 4, stretchedKey));
    var keyK = this._getByteArray(keyView, 32);
    var keyL = this._getByteArray(keyView, 32);

    if (((this._eofMarkerPos - this._view.tell()) % this.BLOCK_SIZE) != 0) {
        throw "EOF marker not aligned on block boundary?";
    }
    var numRecordBlocks = (this._eofMarkerPos - this._view.tell()) / this.BLOCK_SIZE;
    var recordView = this._dataViewFromPlaintext(TwoFish.decrypt(this._view, numRecordBlocks, keyK, true));

    this.headers = this._parseHeaders(recordView);
    this.records = this._parseRecords(recordView);

    // TODO check hash of plaintext fields - need to do JUST the data, no padding.

    // clean up raw data
    delete this._view;
    delete this._eofMarkerPos;
},

sortRecordsByTitle: function() {
    this.records = this.records.sort(function(a, b) {
        return a.title.toLocaleLowerCase().localeCompare(b.title.toLocaleLowerCase());
    });
},

_parseHeaders: function(recordView) {
    var headers = {};
    var fieldType = undefined;
    while(fieldType != 0xff) {
        var recordBegin = recordView.tell();

        if (recordBegin >= recordView.byteLength) {
            break; // <-----
        }

        var fieldSize = recordView.getUint32();
        fieldType = recordView.getUint8();
        switch(fieldType) {
        case 0x00: // Version
            headers.versionNumberOffset = recordView.tell() & ~(this.BLOCK_SIZE - 1);
            headers.versionNumber = recordView.getUint16();
            break;
        case 0x01: // UUID
            headers.UUID = Crypto.util.bytesToHex(this._getByteArray(recordView, 16));
            break;
        case 0x04: // Last saved time
            headers.lastSaveTime = new Date(recordView.getUint32() * 1000);
            break;
        case 0x06: // Last save app
            headers.lastSaveApp = this._getString(recordView, fieldSize);
            break;
        case 0x07: // Last save user
            headers.lastSaveUser = this._getString(recordView, fieldSize);
            break;
        case 0x08: // Last save host
            headers.lastSaveHost = this._getString(recordView, fieldSize);
            break;
        case 0x09: // Database name
            headers.dbName = this._getString(recordView, fieldSize);
            break;
        case 0xff: // END
            break;
        default: // unknown or unimportant
            recordView.seek(recordView.tell() + fieldSize);
        }
        this._alignToBlockBoundary(recordView, fieldSize);
    }
    return headers;
},

_parseRecords: function(recordView) {
    var currentRecord = {};
    var records = [];
    while (recordView.tell() < recordView.byteLength) {
        var fieldSize = recordView.getUint32();
        var fieldType = recordView.getUint8();
        var recordBegin = recordView.tell();
        switch(fieldType) {
        case 0x03: // Title
            currentRecord.title = this._getString(recordView, fieldSize);
            break;
        case 0x04: // Username
            currentRecord.username = this._getString(recordView, fieldSize);
            break;
        case 0x05: // Notes
            currentRecord.notes = this._getString(recordView, fieldSize);
            break;
        case 0x06: // Password
            currentRecord.password = this._getString(recordView, fieldSize);
            break;
        case 0x0d: // URL
            currentRecord.URL = this._getString(recordView, fieldSize);
            break;
        case 0x14: // Email
            currentRecord.email = this._getString(recordView, fieldSize);
            break;
        case 0xff: // END
            records.push(currentRecord);
            currentRecord = {};
            break;
        default: // unknown or unimportant
            recordView.seek(recordView.tell() + fieldSize);
        }
        this._alignToBlockBoundary(recordView, fieldSize);
    }

    return records;
},

_dataViewFromPlaintext: function(buffer) {
    return new jDataView(jDataView.createBuffer.apply(null, buffer));
},

// if the last thing we read was 0-length, always align to next block, otherwise we'll loop forever!
_alignToBlockBoundary: function(view, lastFieldSize) {
    var off = view.tell() % this.BLOCK_SIZE;
    if (off || lastFieldSize == 0) {
        view.seek(view.tell() + this.BLOCK_SIZE - off);
    }
},

_stretchKeySHA256: function(key, salt, iter) {
    key = Crypto.charenc.Binary.stringToBytes(key+salt);
    for (var i = iter; i >= 0; i--) {
        key = Crypto.SHA256(key, {asBytes: true });
    }
    return key;
},

_getHexStringFromBytes: function(view, byteCount) {
    return Crypto.util.bytesToHex(this._getByteArray(view, byteCount));
},

_getByteArray: function(view, byteCount, offset) {
    if (offset !== undefined) {
        view.seek(offset);
    }
    var bytes = new Array(byteCount);
    for(var i = 0; i < byteCount; i++) {
        bytes[i] = view.getUint8();
    }
    return bytes;
},

_getString: function(view, length, offset) {
    return Crypto.charenc.Binary.bytesToString(this._getByteArray(view, length, offset));            
}

});
