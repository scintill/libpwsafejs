function PWSafeDB(buffer) {
    if (((typeof ArrayBuffer !== 'undefined') && (buffer instanceof ArrayBuffer)) || typeof buffer == 'string') {
        this._buffer = buffer;
    } else if (buffer instanceof Object) {
        // allow "casting" after de-JSON from the worker
        this.records = buffer.records;
    }
}


PWSafeDB.isWebWorker = typeof importScripts != 'undefined';

PWSafeDB.downloadAndDecrypt = function(url, key, callback, forceNoWorker) {
    var useWebWorker = !forceNoWorker && window.Worker;

    var getAndDecrypt = function() {
        jQuery.ajax({
            url: url,
            dataType: 'dataview',
            cache: false,
            success: function(view) {
                if (useWebWorker) {
                    var worker = new Worker(jQuery('script[src$="pwsafedb.js"]').attr('src'));
                    worker.onmessage = function(event) {
                        if (typeof event.data == 'string') {
                            callback(event.data);
                        } else {
                            callback(new PWSafeDB(event.data));
                        }
                    };

                    // Chrome (at least) had problems passing the whole jDataView to the worker
                    worker.postMessage({buffer: view.buffer, key: key});
                } else {
                    new PWSafeDB(view.buffer).decrypt(key, function(pdb) { callback(pdb); });
                }
            },
            error: function(jqXHR, textStatus) {
                callback("AJAX error. Status: "+textStatus);
            }
        });
    }

    if (useWebWorker || typeof Crypto.HMACAsync != 'undefined') {
        getAndDecrypt.apply(this);
    } else {
        // load the async libraries since we will need them
        // TODO find some reliable way to do this in the background since we won't be needing it for awhile?
        jQuery.ajax({
            url: jQuery('script[src$="crypto-sha256-hmac.js"]').attr('src').replace('.js', '-async.js'),
            dataType: "script",
            error: function(jqXHR, textStatus) { callback("AJAX async-load extra dependecy error "+textStatus); },
            success: (function(thiz) { return function() {
                getAndDecrypt.apply(thiz);
            }; })(this)});
    }
}


PWSafeDB.prototype.BLOCK_SIZE = 16;

PWSafeDB.prototype.decrypt = function(passphrase, callback) {
    this._view = new jDataView(this._buffer, undefined, undefined, true /* little-endian */);

    this._chunkWork(function() {

        var valid = this._validateFile();
        if (typeof valid == "string") {
            callback(valid);
            return; // <----
        }

        var keys = this._getDecryptionKeys(passphrase);
        if (typeof keys == "string") {
            callback(keys);
            return; // <----
        }

        var recordView = this._decryptRecords(keys);
        if (typeof recordView == "string") {
            callback(recordView);
            return; // <----
        }

        this._chunkWork(function() {

            this._readAllRecords(recordView);

            this._chunkWork(function() {

                this._verifyHMAC(keys, (function(pdb) { return function(matched) {
                    // clean up raw data
                    try {
                        delete this._view;
                        delete this._eofMarkerPos;
                    } catch(e) {} // IE has problems with these deletes -- not sure why
                    if (!matched) {
                        callback("HMAC didn't match -- something may be corrupted");
                        return; // <----
                    } else {
                        callback(pdb);
                        return; // <----
                    }
                }; })(this));
            });
        });
    });
};

PWSafeDB.prototype._validateFile = function() {
    if (this._getString(this._view, 4) != "PWS3") {
        return "Not a PWS v3 file";
    }

    this._eofMarkerPos = this._view.byteLength - 32 - this.BLOCK_SIZE;

    var eofMarker = null;
    if (this._eofMarkerPos > 0) {
        eofMarker = this._getString(this._view, this.BLOCK_SIZE, this._eofMarkerPos);
    }

    if (eofMarker != "PWS3-EOFPWS3-EOF") {
        return "No EOF marker found - not a valid v3 file, or it's corrupted";
    }

    return true;
};

PWSafeDB.prototype._decryptRecords = function(keys) {
    if (((this._eofMarkerPos - this._view.tell()) % this.BLOCK_SIZE) != 0) {
        return "EOF marker not aligned on block boundary?";
    }
    var numRecordBlocks = (this._eofMarkerPos - this._view.tell()) / this.BLOCK_SIZE;
    
    return this._dataViewFromPlaintext(TwoFish.decrypt(this._view, numRecordBlocks, keys.K, true));
};

PWSafeDB.prototype._readAllRecords = function(recordView) {
    // prepare the hash of plaintext fields
    this._isHashing = false;
    this._hashBytes = [];

    // read all fields
    this._parseHeaders(recordView);
    this.records = this._parseRecords(recordView);
};

PWSafeDB.prototype._verifyHMAC = function(keys, callback) {
    // check hash of plaintext fields
    this._view.seek(this._eofMarkerPos+this.BLOCK_SIZE);
    var expectedHMAC = this._getHexStringFromBytes(this._view, 32);

    if (PWSafeDB.isWebWorker) {
        var actualHMAC = Crypto.HMAC(Crypto.SHA256, this._hashBytes, keys.L, {asHex: true});
        callback(expectedHMAC === actualHMAC);
    } else {
        Crypto.HMACAsync(Crypto.SHA256Async, this._hashBytes, keys.L, {asHex: true}, function(actualHMAC) {
            callback(expectedHMAC === actualHMAC);
        });
    }
};

PWSafeDB.prototype._getDecryptionKeys = function(passphrase) {
    // validate password and stretch it to get the decryption key
    var salt = this._getString(this._view, 32, 4);
    var iter = this._view.getUint32();
    var expectedStretchedKeyHash = this._getHexStringFromBytes(this._view, 32);
    var stretchedKey = this._stretchKeySHA256(passphrase, salt, iter);
    var stretchedKeyHash = Crypto.SHA256(stretchedKey);

    if (expectedStretchedKeyHash !== stretchedKeyHash) {
        return "Incorrect password";
    }

    var keyView = this._dataViewFromPlaintext(TwoFish.decrypt(this._view, 4, stretchedKey));
    var keys = {};
    keys.K = this._getByteArray(keyView, 32);
    keys.L = this._getByteArray(keyView, 32);

    return keys;
};

PWSafeDB.prototype.sortRecordsByTitle = function() {
    this.records = this.records.sort(function(a, b) {
        return a.title.toLocaleLowerCase().localeCompare(b.title.toLocaleLowerCase());
    });
};

PWSafeDB.prototype._parseHeaders = function(recordView) {
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
};

PWSafeDB.prototype._parseRecords = function(recordView) {
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
};

PWSafeDB.prototype._readField = function(view, isHeader) {
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
};

PWSafeDB.prototype._dataViewFromPlaintext = function(buffer) {
    return new jDataView(jDataView.createBuffer.apply(null, buffer), undefined, undefined, true /* little-endian */);
};

PWSafeDB.prototype._alignToBlockBoundary = function(view) {
    var off = view.tell() % this.BLOCK_SIZE;
    if (off) {
        view.seek(view.tell() + this.BLOCK_SIZE - off);
    }
};

PWSafeDB.prototype._stretchKeySHA256 = function(key, salt, iter) {
    key = Crypto.charenc.Binary.stringToBytes(key+salt);
    for (var i = iter; i >= 0; i--) {
        key = Crypto.SHA256(key, {asBytes: true });
    }
    return key;
};

PWSafeDB.prototype._getHexStringFromBytes = function(view, byteCount) {
    return Crypto.util.bytesToHex(this._getByteArray(view, byteCount));
};

PWSafeDB.prototype._getByteArray = function(view, byteCount, offset) {
    if (offset !== undefined) {
        view.seek(offset);
    }
    var bytes = new Array(byteCount);
    for(var i = 0; i < byteCount; i++) {
        bytes[i] = view.getUint8();
    }
    return bytes;
};

PWSafeDB.prototype._getString = function(view, length, offset) {
    var bytes = this._getByteArray(view, length, offset);
    return Crypto.charenc.Binary.bytesToString(bytes);
};

PWSafeDB.prototype._updateHash = function(bytes, field) {
    if (field.isHeader && field.type == 0x00) {
        this._isHashing = true;
    }

    if (this._isHashing) {
        this._hashBytes = this._hashBytes.concat(bytes);                 
    }
};

PWSafeDB.prototype._chunkWork = function(chunkFunc) {
    if (PWSafeDB.isWebWorker) {
        chunkFunc.apply(this);
    } else {
        var thiz = this;
        window.setTimeout(function() {
            return chunkFunc.apply(thiz);
        }, 1);
    }
};


// Web Worker interface
if (PWSafeDB.isWebWorker) {
    importScripts('jDataView/src/jdataview.js', 'crypto-sha256-hmac.js', 'twofish.js');

    onmessage = function(event) {
        var data = event.data;
        new PWSafeDB(data.buffer).decrypt(data.key, function(result) {
            postMessage(result);
        });
    };

}
