function PWSafeDB() {}

// constants
PWSafeDB.isWebWorker = typeof importScripts != 'undefined'; // am I a web worker?
PWSafeDB.BLOCK_SIZE = 16;


// Load and return a database from the given url and passphrase
PWSafeDB.downloadAndDecrypt = function(url, passphrase, callback, options) {
    if (options === undefined) {
        options = {};
    }

    var useWebWorker = !options.forceNoWorker && window.Worker;

    jQuery.ajax({
        url: url,
        dataType: 'dataview',
        cache: false,
        success: function(dataview) {
            if (useWebWorker) {
                var worker = new Worker(jQuery('script[src$="pwsafedb.js"]').attr('src'));
                worker.onmessage = function(event) {
                    var ctor = window[event.data.type] || Error;
                    var result = new ctor();
                    for (var k in event.data) {
                        if (k != 'type') {
                            result[k] = event.data[k];
                        }
                    }
                    callback(result); return;
                };

                // we discard this jDataView because we need to set endianness
                worker.postMessage({buffer: dataview.buffer, passphrase: passphrase, options: options});
            } else {
                try {
                    new PWSafeDB()._decrypt(dataview.buffer, passphrase, options, function(pdb) { callback(pdb); return; });
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

PWSafeDB.extend = function(targetOb, properties) {
    for (var k in properties) {
        targetOb[k] = properties[k];
    }
};

PWSafeDB.extend(PWSafeDB.prototype, {

sortRecordsByTitle: function() {
    this.records = this.records.sort(function(a, b) {
        return a.title.toLocaleLowerCase().localeCompare(b.title.toLocaleLowerCase());
    });
},

_decrypt: function(buffer, passphrase, options, callback) {
    this._view = new jDataView(buffer, undefined, undefined, true /* little-endian */);

    this._chunkWork(function() {
        this._validateFile();
        var keys = this._getDecryptionKeys(passphrase);
        if (keys === false) {
            throw new Error("Incorrect passphrase");
        }
        var fieldView = this._decryptFields(keys);

        this._chunkWork(function() {

            this._readAllRecords(fieldView, options.strictFieldTypeCheck);

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

_readAllRecords: function(fieldView, strictFieldType) {
    // prepare the hash of plaintext fields
    this._isHashing = false;
    this._hashBytes = [];

    // read all fields
    this.headers = this._parseHeaders(fieldView, strictFieldType);
    this.records = this._parseRecords(fieldView, strictFieldType);
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

_parseHeaders: function(fieldView, strictFieldType) {
    var field;
    var headers = {};

    while(field === undefined || field.type != 0xff) {
        if (fieldView.tell() >= fieldView.byteLength) {
            break; // <-----
        }

        field = this._readField(fieldView, true);
        switch (field.type) {
        case 0xff: // end
            break;
        case 0x00:
            headers.version = field.uint16();
            break;
        case 0x01:
            headers.uuid = field.uuid();
            break;
        case 0x02:
            headers.nonDefaultPrefs = field.str();
            break;
        case 0x03:
            headers.treeDisplayStatus = field.str();
            break;
        case 0x04:
            headers.lastSaveTime = field.epochTime();
            break;
        case 0x06:
            headers.lastSaveApp = field.str();
            break;
        case 0x07:
            headers.lastSaveUser = field.str();
            break;
        case 0x08:
            headers.lastSaveHost = field.str();
            break;
        case 0x0f:
            var fieldStr = field.str();
            var pos = 0;
            var length = parseInt(fieldStr.substring(0, pos += 2), 16);
            var entries = [];
            for (var i = 0; i < length; i++) {
                entries[i] = fieldStr.substring(pos, pos += 32);
            }
            headers.recentlyUsedEntries = entries;
            break;
        default: // unknown
            if (strictFieldType) {
                delete field.view;
                throw new Error("unknown header field " + JSON.stringify(field));
            }
        }
    }

    return headers;
},

_parseRecords: function(fieldView, strictFieldType) {
    var currentRecord = {};
    var records = [];

    var fieldStr, pos;

    while (fieldView.tell() < fieldView.byteLength) {
        var field = this._readField(fieldView);

        // I'm seeing an empty field of type zero for some reason
        if (field.type === 0 && field.bytes.length === 0) {
            continue; // <---
        }

        switch(field.type) {
        case 0x01:
            currentRecord.uuid = field.uuid();
            break;
        case 0x02:
            currentRecord.group = field.str();
            break;
        case 0x03:
            currentRecord.title = field.str();
            break;
        case 0x04:
            currentRecord.username = field.str();
            break;
        case 0x05:
            currentRecord.notes = field.str();
            break;
        case 0x06:
            currentRecord.password = field.str();
            break;
        case 0x07:
            currentRecord.createTime = field.epochTime();
            break;
        case 0x08:
            currentRecord.passphraseModifyTime = field.epochTime();
            break;
        case 0x0c:
            currentRecord.modifyTime = field.epochTime();
            break;
        case 0x0d:
            currentRecord.URL = field.str();
            break;
        case 0x0e:
            currentRecord.autotype = field.str();
            break;
        case 0x0f:
            fieldStr = field.str();
            var history = {
                isEnabled: field.bytes[0] !== 0,
                maxSize: parseInt(fieldStr.substring(1, 3), 16),
                currentSize: parseInt(fieldStr.substring(3, 5), 16)
            };
            pos = 5;
            var passphrases = history.passphrases = [];
            for (var i = 0; i < history.currentSize; i++) {
                passphrases[i] = {
                    timestamp: new Date(parseInt(fieldStr.substring(pos, pos += 8), 16) * 1000)
                };
                var length = parseInt(fieldStr.substring(pos, pos += 4), 16);
                passphrases[i].passphrase = fieldStr.substring(pos, pos += length);
            }
            currentRecord.passphraseHistory = history;
            break;
        case 0x10:
            fieldStr = field.str();
            pos = 0;
            currentRecord.passphrasePolicy = {
                flags: parseInt(fieldStr.substring(pos, pos += 4), 16),
                length: parseInt(fieldStr.substring(pos, pos += 3), 16),
                minLowercase: parseInt(fieldStr.substring(pos, pos += 3), 16),
                minUppercase: parseInt(fieldStr.substring(pos, pos += 3), 16),
                minDigit: parseInt(fieldStr.substring(pos, pos += 3), 16),
                minSymbol: parseInt(fieldStr.substring(pos, pos += 3), 16)
            };
            break;
        case 0x14:
            currentRecord.emailAddress = field.str();
            break;
        case 0x16:
            currentRecord.ownPassphraseSymbols = field.str();
            break;
        case 0xff: // END
            records.push(currentRecord);
            currentRecord = {};
            break;
        default: // unknown
            if (strictFieldType) {
                delete field.view;
                throw new Error("unknown record field " + JSON.stringify(field));
            }
        }
    }

    return records;
},

_readField: function(view, isHeader) {
    isHeader = !!isHeader; // boolify undefined into false

    var fieldSize = view.getUint32();
    if (view.tell() + fieldSize >= view.byteLength) {
        throw new Error("Invalid field size -- larger than remainder of file");
    }
    var field = new PWSafeDBField(isHeader, view.getUint8());

    field.view = view;
    field.offset = view.tell();
    field.bytes = this._getByteArray(view, fieldSize);

    this._updateHash(field);
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

_updateHash: function(field) {
    if (field.isHeader && field.type === 0x00) {
        this._isHashing = true;
    }

    if (this._isHashing) {
        for (var i in field.bytes) {
            this._hashBytes.push(field.bytes[i]);
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



function PWSafeDBField(isHeader, type) {
    this.isHeader = isHeader;
    this.type = type;
}

PWSafeDB.extend(PWSafeDBField.prototype, {
    str: function() {
        try {
            return Crypto.charenc.UTF8.bytesToString(this.bytes);
        } catch (e) {
            if (e.constructor == URIError) {
                throw new Error("Invalid UTF-8 encoding", e);
            }
            throw e;
        }
    },
    uint16: function() {
        var prevOffset = this.view.tell();
        var n = this.view.getUint16(this.offset);
        this.view.seek(prevOffset);
        return n;
    },
    uint32: function() {
        var prevOffset = this.view.tell();
        var n = this.view.getUint32(this.offset);
        this.view.seek(prevOffset);
        return n;
    },
    epochTime: function() { return new Date(this.uint32() * 1000); },
    uuid: function() { return Crypto.util.bytesToHex(this.bytes); }
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
            new PWSafeDB()._decrypt(data.buffer, data.passphrase, data.options, callback);
        } catch (e) {
            callback(e); return;
        }
    };
}
