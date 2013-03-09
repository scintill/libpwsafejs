function PWSafeDB() {}

// constants
PWSafeDB.isWebWorker = typeof importScripts != 'undefined'; // am I a web worker?
PWSafeDB.BLOCK_SIZE = 16;


// Load and return a database from the given url and passphrase
PWSafeDB.downloadAndDecrypt = function(url, passphrase, callback, forceNoWorker) {
    var useWebWorker = !forceNoWorker && window.Worker;

    jQuery.ajax({
        url: url,
        dataType: 'dataview',
        cache: false,
        success: function(dataview) {
            if (useWebWorker) {
                var worker = new Worker(jQuery('script[src$="pwsafedb.js"]').attr('src'));
                worker.onmessage = function(event) {
                    var result = new window[event.data.type]();
                    for (var k in event.data) {
                        if (k != 'type') {
                            result[k] = event.data[k];
                        }
                    }
                    callback(result); return;
                };

                // we discard this jDataView because we need to set endianness
                worker.postMessage({buffer: dataview.buffer, passphrase: passphrase});
            } else {
                try {
                    new PWSafeDB()._decrypt(dataview.buffer, passphrase, function(pdb) { callback(pdb); return; });
                } catch (e) {
                    callback(e); return;
                }
            }
        },
        error: function(jqXHR, textStatus) {
            callback(new Error("AJAX error. Status: "+textStatus)); return;
        }
    });
};

(function(prototype) {
    for (var k in prototype) {
        PWSafeDB.prototype[k] = prototype[k];
    }
})({

sortRecordsByTitle: function() {
    this.records = this.records.sort(function(a, b) {
        return a.title.toLocaleLowerCase().localeCompare(b.title.toLocaleLowerCase());
    });
},

_decrypt: function(buffer, passphrase, callback) {
    this._view = new jDataView(buffer, undefined, undefined, true /* little-endian */);

    this._chunkWork(function() {
        this._validateFile();
        var keys = this._getDecryptionKeys(passphrase);
        if (keys === false) {
            throw new Error("Incorrect passphrase");
        }
        var fieldView = this._decryptFields(keys);

        this._chunkWork(function() {

            this._readAllRecords(fieldView);

            this._chunkWork(function() {

                this._verifyHMAC(keys, (function(pdb) { return function(matched) {
                    // clean up raw data -- some of it won't be passable through worker interface, and there's no need for it anyway
                    try {
                        delete pdb._eofMarkerPos;
                        delete pdb._hashBytes;
                        delete pdb._isHashing;
                        delete pdb._view;
                    } catch(e) {} // IE has problems with these deletes -- not sure why

                    if (!matched) {
                        callback(new Error("HMAC didn't match -- something may be corrupted"));
                    } else {
                        callback(pdb); return;
                    }
                }; })(this));

            }, callback);
        }, callback);
    }, callback);
},

_validateFile: function() {
    if (this._getBinaryString(this._view, 4) != "PWS3") {
        throw new Error("Not a PWS v3 file");
    }

    this._eofMarkerPos = this._view.byteLength - 32 - PWSafeDB.BLOCK_SIZE;

    var eofMarker = null;
    if (this._eofMarkerPos > 0) {
        eofMarker = this._getBinaryString(this._view, PWSafeDB.BLOCK_SIZE, this._eofMarkerPos);
    }

    if (eofMarker != "PWS3-EOFPWS3-EOF") {
        throw new Error("No EOF marker found - not a valid v3 file, or it's corrupted");
    }

    return true;
},

_decryptFields: function(keys) {
    if (((this._eofMarkerPos - this._view.tell()) % PWSafeDB.BLOCK_SIZE) !== 0) {
        throw new Error("EOF marker not aligned on block boundary?");
    }
    var numFieldBlocks = (this._eofMarkerPos - this._view.tell()) / PWSafeDB.BLOCK_SIZE;

    return this._dataViewFromPlaintext(TwoFish.decrypt(this._view, numFieldBlocks, keys.K, true));
},

_readAllRecords: function(fieldView) {
    // prepare the hash of plaintext fields
    this._isHashing = false;
    this._hashBytes = [];

    // read all fields
    this._parseHeaders(fieldView);
    this.records = this._parseRecords(fieldView);
},

// check hash of plaintext fields
_verifyHMAC: function(keys, callback) {
    var expectedHMAC = this._getBinaryString(this._view, 32, this._eofMarkerPos + PWSafeDB.BLOCK_SIZE);

    if (PWSafeDB.isWebWorker) {
        var actualHMAC = Crypto.HMAC(Crypto.SHA256, this._hashBytes, keys.L, {asString: true});
        callback(expectedHMAC === actualHMAC); return;
    } else {
        Crypto.HMAC(Crypto.SHA256, this._hashBytes, keys.L, {asString: true, callback: function(actualHMAC) {
            callback(expectedHMAC === actualHMAC); return;
        }});
    }
},

// validate password and stretch it to get the decryption key
_getDecryptionKeys: function(passphrase) {
    var salt = this._getByteArray(this._view, 32, 4);
    var iter = this._view.getUint32();
    var expectedStretchedKeyHash = this._getBinaryString(this._view, 32);
    var stretchedKey = this._stretchKeySHA256(Crypto.charenc.UTF8.stringToBytes(passphrase), salt, iter);
    var stretchedKeyHash = Crypto.SHA256(stretchedKey, {asString: true});

    if (expectedStretchedKeyHash !== stretchedKeyHash) {
        return false;
    }

    var keyView = this._dataViewFromPlaintext(TwoFish.decrypt(this._view, 4, stretchedKey));
    var keys = {};
    keys.K = this._getByteArray(keyView, 32);
    keys.L = this._getByteArray(keyView, 32);

    return keys;
},

_parseHeaders: function(fieldView) {
    var field;
    while(field === undefined || field.type != 0xff) {
        if (fieldView.tell() >= fieldView.byteLength) {
            break; // <-----
        }

        field = this._readField(fieldView, true);
        if (field.type == 0xff) {
            break;
        } else { // unknown or unimportant
            // updateHash() handles all I care about for the version number record -- that is, where it is, for the HMAC verify
        }
    }
},

_parseRecords: function(fieldView) {
    var currentRecord = {};
    var records = [];
    while (fieldView.tell() < fieldView.byteLength) {
        var field = this._readField(fieldView);
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
    // TODO handle non-string fields
    try {
        field.valueStr = Crypto.charenc.UTF8.bytesToString(bytes);
    } catch (e) {
        // probably a UTF-8 decoding error, which is probably because this field isn't really a string
    }
    this._updateHash(bytes, field);

    this._alignToBlockBoundary(view);

    return field;
},

_dataViewFromPlaintext: function(buffer) {
    return new jDataView(jDataView.createBuffer(buffer), undefined, undefined, true /* little-endian */);
},

_alignToBlockBoundary: function(view) {
    var off = view.tell() % PWSafeDB.BLOCK_SIZE;
    if (off) {
        view.seek(view.tell() + PWSafeDB.BLOCK_SIZE - off);
    }
},

_stretchKeySHA256: function(key, salt, iter) {
    key = key.concat(salt);
    for (var i = iter; i >= 0; i--) {
        key = Crypto.SHA256(key, {asBytes: true });
    }
    return key;
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

_getBinaryString: function(view, length, offset) {
    var bytes = this._getByteArray(view, length, offset);
    return Crypto.charenc.Binary.bytesToString(bytes);
},

_updateHash: function(bytes, field) {
    if (field.isHeader && field.type === 0x00) {
        this._isHashing = true;
    }

    if (this._isHashing) {
        for (var i in bytes) {
            this._hashBytes.push(bytes[i]);
        }
    }
},

_chunkWork: function(chunkFunc, exceptionHandler) {
    if (PWSafeDB.isWebWorker) {
        try {
            chunkFunc.apply(this);
        } catch (e) {
            exceptionHandler(e);
        }
    } else {
        var thiz = this;
        window.setTimeout(function() {
            try {
                return chunkFunc.apply(thiz);
            } catch (e) {
                exceptionHandler(e);
            }
        }, 1);
    }
}

});


// If inside web worker, load scripts and message handler
if (PWSafeDB.isWebWorker) {
    importScripts('jDataView/src/jdataview.js', 'crypto-sha256-hmac.js', 'twofish.js');

    onmessage = function(event) {
        var data = event.data;
        var callback = function(result) {
            if (result instanceof Error) {
                // getting clone error trying to pass it directly
                postMessage({type: result.name, message: result.message, name: result.name, stack: result.stack});
            } else {
                postMessage({type: "PWSafeDB", records: result.records});
            }
        };

        try {
            new PWSafeDB()._decrypt(data.buffer, data.passphrase, callback);
        } catch (e) {
            callback(e); return;
        }
    };
}
