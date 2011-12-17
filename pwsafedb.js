function PWSafeDB(data) {
    this._view = new jDataView(data);
}

jQuery.extend(PWSafeDB.prototype, {

BLOCK_SIZE: 16,

validate: function() {
    if (this._view.getString(4) != "PWS3") {
        throw "Not a PWS v3 file";
    }

    this._eofMarkerPos = this._view.length - 32 - this.BLOCK_SIZE;
    if (this._eofMarkerPos <= 0 || (this._view.getString(this.BLOCK_SIZE, this._eofMarkerPos) != "PWS3-EOFPWS3-EOF")) {
        throw "No EOF marker found - not a valid v3 file, or it's corrupted";
    }

    return true;
},

decrypt: function(key) {
    this.validate();

    var salt = this._view.getString(32, 4);
    var iter = this._view.getUint32();
    var expectedStretchedKeyHash = this._getHexStringFromBytes(this._view, 32);
    var stretchedKey = this._stretchKeySHA256(key, salt, iter);
    var stretchedKeyHash = Crypto.SHA256(stretchedKey);

    if (expectedStretchedKeyHash !== stretchedKeyHash) {
        throw "Incorrect password";
    }

    var keyView = this._dataViewFromPlaintext(TwoFish.decrypt(this._view, 4, stretchedKey));
    var K = this._getByteArray(keyView, 32);
    var L = this._getByteArray(keyView, 32);

    var numRecordBlocks = (this._eofMarkerPos - this._view.tell()) / this.BLOCK_SIZE;
    var recordView = this._dataViewFromPlaintext(TwoFish.decrypt(this._view, numRecordBlocks, K, true));

    this.headers = this._parseHeaders(recordView);
    this.records = this._parseRecords(recordView);

    // check hash of plaintext fields
    /*this._view.seek(this._eofMarkerPos+this.BLOCK_SIZE);
    recordView.seek(this._headers.versionNumberOffset);
    var actualHMAC = Crypto.HMAC(Crypto.SHA256,
        this._getByteArray(recordView, recordView.length-this._headers.versionNumberOffset),
        L, {asBytes: true});
    var expectedHMAC = this._getByteArray(this._view, 32);

    if (expectedHMAC !== actualHMAC) {
        throw "HMAC didn't match -- something may be corrupted";
    }*/

    // sort by title
    this.records = this.records.sort(function(a, b) {
        return a.title.toLocaleLowerCase().localeCompare(b.title.toLocaleLowerCase());
    });

    // clean up raw data
    delete this._view;
    delete this._eofMarkerPos;
},

_parseHeaders: function(recordView) {
    var headers = {};
    var fieldType = undefined;
    while(fieldType != 0xff) {
        var recordBegin = recordView.tell();

        if (recordBegin >= recordView.length) {
            break; // <-----
        }

        var fieldSize = recordView.getUint32();
        fieldType = recordView.getUint8();
        switch(fieldType) {
        case 0x00: // Version
            headers.versionNumber = recordView.getUint16();
            headers.versionNumberOffset = recordView.tell() & ~(this.BLOCK_SIZE - 1);
            break;
        case 0x01: // UUID
            headers.UUID = Crypto.util.bytesToHex(this._getByteArray(recordView, 16));
            break;
        case 0x04: // Last saved time
            headers.lastSaveTime = new Date(recordView.getUint32() * 1000);
            break;
        case 0x06: // Last save app
            headers.lastSaveApp = recordView.getString(fieldSize);
            break;
        case 0x07: // Last save user
            headers.lastSaveUser = recordView.getString(fieldSize);
            break;
        case 0x08: // Last save host
            headers.lastSaveHost = recordView.getString(fieldSize);
            break;
        case 0x09: // Database name
            headers.dbName = recordView.getString(fieldSize);
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
    while (recordView.tell() < recordView.length) {
        var fieldSize = recordView.getUint32();
        var fieldType = recordView.getUint8();
        var recordBegin = recordView.tell();
        switch(fieldType) {
        case 0x03: // Title
            currentRecord.title = recordView.getString(fieldSize);
            break;
        case 0x04: // Username
            currentRecord.username = recordView.getString(fieldSize);
            break;
        case 0x05: // Notes
            currentRecord.notes = recordView.getString(fieldSize);
            break;
        case 0x06: // Password
            currentRecord.password = recordView.getString(fieldSize);
            break;
        case 0x0d: // URL
            currentRecord.URL = recordView.getString(fieldSize);
            break;
        case 0x14: // Email
            currentRecord.email = recordView.getString(fieldSize);
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

_getByteArray: function(view, byteCount) {
    var bytes = new Array(byteCount);
    for(var i = 0; i < byteCount; i++) {
        bytes[i] = view.getUint8();
    }
    return bytes;
}

});
