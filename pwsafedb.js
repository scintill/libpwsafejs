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

    // validate password and stretch it to get the decryption key
    var salt = this._getString(this._view, 32, 4);
    var iter = this._view.getUint32();
    var expectedStretchedKeyHash = this._getHexStringFromBytes(this._view, 32);
    var stretchedKey = this._stretchKeySHA256(key, salt, iter);
    var stretchedKeyHash = Crypto.SHA256(stretchedKey);

    if (expectedStretchedKeyHash !== stretchedKeyHash) {
        throw "Incorrect password";
    }

    // get keys, decrypt all data
    var keyView = this._dataViewFromPlaintext(TwoFish.decrypt(this._view, 4, stretchedKey));
    var keyK = this._getByteArray(keyView, 32);
    var keyL = this._getByteArray(keyView, 32);

    if (((this._eofMarkerPos - this._view.tell()) % this.BLOCK_SIZE) != 0) {
        throw "EOF marker not aligned on block boundary?";
    }
    var numRecordBlocks = (this._eofMarkerPos - this._view.tell()) / this.BLOCK_SIZE;
    var recordView = this._dataViewFromPlaintext(TwoFish.decrypt(this._view, numRecordBlocks, keyK, true));

    // prepare the hash of plaintext fields
    this._isHashing = false;
    this._hashBytes = [];

    // read all fields
    this._parseHeaders(recordView);
    this.records = this._parseRecords(recordView);

    // check hash of plaintext fields
    this._view.seek(this._eofMarkerPos+this.BLOCK_SIZE);
    var actualHMAC = Crypto.HMAC(Crypto.SHA256, this._hashBytes, keyL, {asHex: true});
    var expectedHMAC = this._getHexStringFromBytes(this._view, 32);

    if (expectedHMAC !== actualHMAC) {
        throw "HMAC didn't match -- something may be corrupted";
    }

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
    var field = undefined;
    while(field === undefined || field.type != 0xff) {
        if (recordView.tell() >= recordView.byteLength) {
            break; // <-----
        }

        var field = this._readField(recordView, true);
        switch(field.type) {
        case 0xff: // END
            break;
        default: // unknown or unimportant
            // updateHash handles all I care about for the version number record -- that is, where it is, for the HMAC verify
        }
    }
},

_parseRecords: function(recordView) {
    var currentRecord = {};
    var records = [];
    while (recordView.tell() < recordView.byteLength) {
        var field = this._readField(recordView);
        switch(field.type) {
        case 0x03: // Title
            currentRecord.title = field.valueStr;
            break;
        case 0x04: // Username
            currentRecord.username = field.valueStr;
            break;
        case 0x05: // Notes
            currentRecord.notes = field.valueStr;
            break;
        case 0x06: // Password
            currentRecord.password = field.valueStr;
            break;
        case 0x0d: // URL
            currentRecord.URL = field.valueStr;
            break;
        case 0xff: // END
            records.push(currentRecord);
            currentRecord = {};
            break;
        default: // unknown or unimportant
        }
    }

    return records;
},

_readField: function(view, isHeader) {
    isHeader = !!isHeader; // boolify undefined into false

    var fieldSize = view.getUint32();
    var field = {
        isHeader: isHeader,
        type: view.getUint8()
    };
    var bytes = this._getByteArray(view, fieldSize);
    // TODO figure out best way to handle non-string fields?
    field.valueStr = Crypto.charenc.Binary.bytesToString(bytes);
    this._updateHash(bytes, field);

    this._alignToBlockBoundary(view);

    return field;
},

_dataViewFromPlaintext: function(buffer) {
    return new jDataView(jDataView.createBuffer.apply(null, buffer));
},

_alignToBlockBoundary: function(view) {
    var off = view.tell() % this.BLOCK_SIZE;
    if (off) {
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
    var bytes = this._getByteArray(view, length, offset);
    return Crypto.charenc.Binary.bytesToString(bytes);
},

_updateHash: function(bytes, field) {
    if (field.isHeader && field.type == 0x00) {
        this._isHashing = true;
    }

    if (this._isHashing) {
        this._hashBytes = this._hashBytes.concat(bytes);                 
    }
}

});
