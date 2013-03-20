(function(exports, global) {

function PWSafeDB() {}

// constants
PWSafeDB.isWebWorker = typeof importScripts != 'undefined'; // am I a web worker?
PWSafeDB.isNode = typeof module !== 'undefined';
PWSafeDB.BLOCK_SIZE = 16;
PWSafeDB.MIN_HASH_ITERATIONS = 2048; // recommended in specs

if (PWSafeDB.isNode) {
    var fs = require('fs');
}

// Load and return a database from the given url and passphrase
PWSafeDB.decryptFromUrl = function(url, passphrase, options, callback) {
    if (options === undefined) {
        options = {};
    }

    var useWebWorker = !options.forceNoWorker && (typeof window != 'undefined' && window.Worker);

    if (!PWSafeDB.isNode) {
        jQuery.ajax({
            url: url,
            dataType: 'dataview',
            cache: false,
            success: function(dataview) {
                if (useWebWorker) {
                    var worker = new Worker(jQuery('script[src$="pwsafedb.js"]').attr('src'));
                    worker.onmessage = function(event) {
                        var ctor = global[event.data.type] || Error;
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
                        new PWSafeDB().decrypt(dataview.buffer, passphrase, options, callback);
                    } catch (e) {
                        callback(e); return;
                    }
                }
            },
            error: function(jqXHR, textStatus) {
                callback(new Error("AJAX error. Status: "+textStatus)); return;
            }
        });
    } else { // node js
        fs.readFile(url, function(err, buffer) {
            if (err) {
                callback(err);
                return;
            }
            new PWSafeDB().decrypt(buffer, passphrase, options, callback);
        });
    }
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

decrypt: function(buffer, passphrase, options, callback) {
    this._view = this._newjDataView(buffer);

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
    if (this._view.getBinaryString(4) != "PWS3") {
        throw new Error("Not a PWS v3 file");
    }

    this._eofMarkerPos = this._view.byteLength - 32 - PWSafeDB.BLOCK_SIZE;

    var eofMarker = null;
    if (this._eofMarkerPos > 0) {
        eofMarker = this._view.getBinaryString(PWSafeDB.BLOCK_SIZE, this._eofMarkerPos);
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

    return this._newjDataView(TwoFish.decrypt(this._view, numFieldBlocks, keys.K, true));
},

// check hash of plaintext fields
_verifyHMAC: function(keys, callback) {
    var expectedHMAC = this._view.getBinaryString(32, this._eofMarkerPos + PWSafeDB.BLOCK_SIZE);

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
    var salt = this._view.getBytes(32, 4);
    var iter = this._view.getUint32();
    var expectedStretchedKeyHash = this._view.getBinaryString(32);
    var stretchedKey = this._stretchPassphrase(passphrase, salt, iter);
    var stretchedKeyHash = Crypto.SHA256(stretchedKey, {asString: true});

    if (expectedStretchedKeyHash !== stretchedKeyHash) {
        return false;
    }

    var keyView = this._newjDataView(TwoFish.decrypt(this._view, 4, stretchedKey));
    var keys = { K: keyView.getBytes(32), L: keyView.getBytes(32) };

    return keys;
},

_readAllRecords: function(fieldView, strictFieldType) {
    // prepare the hash of plaintext fields
    this._isHashing = false;
    this._hashBytes = [];

    // read headers
    this.headers = (function() {
        var field;
        var headers = {};

        fieldView.seek(0);
        while(field === undefined || field.type != 0xff) {
            if (fieldView.tell() >= fieldView.byteLength) {
                break; // <-----
            }

            field = this._readField(fieldView, true);
            switch (field.type) {
            case 0xff: // end
                break;
            case 0x00:
                headers.version = field.readUint16();
                break;
            case 0x01:
                headers.uuid = field.readUuid();
                break;
            case 0x02:
                headers.nonDefaultPrefs = field.readStr();
                break;
            case 0x03:
                headers.treeDisplayStatus = field.readStr();
                break;
            case 0x04:
                headers.lastSaveTime = field.readEpochTime();
                break;
            case 0x06:
                headers.lastSaveApp = field.readStr();
                break;
            case 0x07:
                headers.lastSaveUser = field.readStr();
                break;
            case 0x08:
                headers.lastSaveHost = field.readStr();
                break;
            case 0x0f:
                var fieldStr = field.readStr();
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
    }).call(this);

    // read records
    this.records = (function() {
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
                currentRecord.uuid = field.readUuid();
                break;
            case 0x02:
                currentRecord.group = field.readStr();
                break;
            case 0x03:
                currentRecord.title = field.readStr();
                break;
            case 0x04:
                currentRecord.username = field.readStr();
                break;
            case 0x05:
                currentRecord.notes = field.readStr();
                break;
            case 0x06:
                currentRecord.password = field.readStr();
                break;
            case 0x07:
                currentRecord.createTime = field.readEpochTime();
                break;
            case 0x08:
                currentRecord.passphraseModifyTime = field.readEpochTime();
                break;
            case 0x0c:
                currentRecord.modifyTime = field.readEpochTime();
                break;
            case 0x0d:
                currentRecord.URL = field.readStr();
                break;
            case 0x0e:
                currentRecord.autotype = field.readStr();
                break;
            case 0x0f:
                fieldStr = field.readStr();
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
                fieldStr = field.readStr();
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
                currentRecord.emailAddress = field.readStr();
                break;
            case 0x16:
                currentRecord.ownPassphraseSymbols = field.readStr();
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
    }).call(this);

},

_readField: function(view, isHeader) {
    isHeader = !!isHeader; // boolify undefined into false

    var fieldSize = view.getUint32();
    var offset = view.tell()+1;
    if (offset + fieldSize >= view.byteLength) {
        throw new Error("Invalid field size at offset " + (offset-5) + " -- larger than remainder of file");
    }

    var field = new PWSafeDBField(isHeader, view.getUint8(), view, offset, view.getBytes(fieldSize));
    this._updateHash(field);
    this._alignToBlockBoundary(view);

    return field;
},

_newjDataView: function(buffer) {
    var view = new jDataView(buffer, undefined, undefined, true /* little-endian */);
    // patch some stuff to help me keep things straight
    view.getBinaryString = view.getString;
    view.getString = null;
    view.writeBinaryString = view.writeString;
    view.writeString = null;

    return view;
},

_alignToBlockBoundary: function(view) {
    var off = view.tell() % PWSafeDB.BLOCK_SIZE;
    if (off) {
        view.seek(view.tell() + PWSafeDB.BLOCK_SIZE - off);
    }
},

_stretchPassphrase: function(passphrase, salt, iter) {
    var key = Crypto.charenc.UTF8.stringToBytes(passphrase).concat(salt);
    for (var i = iter; i >= 0; i--) {
        key = Crypto.SHA256(key, {asBytes: true });
    }
    return key;
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
        setTimeout(function() {
            try {
                return chunkFunc.apply(thiz);
            } catch (e) {
                exceptionHandler(e);
            }
        }, 1);
    }
},

_serializeFields: function() {
    /**
     * We have to give a size when making a jDataView, but it's hard to calculate.
     * Rather than guessing an upper bound and trimming it down when we're done, I'll
     * just implement what I need of the jDataView interface to have a growable buffer.
     *
     * It's crazy, but seems to be the simplest way to cover all cases with least amount of code.
     */
    var view = {
        buffer: [],
        offset: 0,
        writeBytes: function(a) {
            for (var i = 0; i < a.length; i++) {
                this.buffer[this.offset++] = a[i] & 0xff;
            }
        },
        getBytes: function(n, offset) {
            if (offset === undefined) offset = this.offset;
            return this.buffer.slice(offset, this.offset = offset + n);
        },
        writeUint8: function(n) { this.buffer[this.offset++] = n & 0xff; },
        getUint8: function(offset) {
            if (offset === undefined) offset = this.offset;
            var v = this.buffer[offset];
            this.offset = offset+1;
            return v;
        },
        writeUint16: function(n) { this.writeBytes([n, n >>> 8]); },
        writeUint32: function(n) { this.writeBytes([n, (n >>> 8) & 0xff, (n >>> 16) & 0xff, n >>> 24]); },
        writeBinaryString: function(str) { this.writeBytes(Crypto.charenc.Binary.stringToBytes(str)); },
        tell: function() { return this.offset; },
        seek: function(offset) { this.offset = offset; }
    };

    var types, str, i, k, j;

    // prepare HMAC
    this._isHashing = false;
    this._hashBytes = [];

    // remember that a raw view.writeString won't write UTF-8.
    // Also be careful calculating string lengths as UTF-8 could change that.
    var writeString = function(str, type) {
        var bytes = Crypto.charenc.UTF8.stringToBytes(str);
        view.writeUint32(bytes.length);
        view.writeUint8(type);
        view.writeBytes(bytes);
    },
    writeTimestamp = function(date, type) {
        view.writeUint32(4);
        view.writeUint8(type);
        view.writeUint32(date.getTime() / 1000);
    },
    writeUuid = function(uuidStr, type) {
        view.writeUint32(16);
        view.writeUint8(type);
        view.writeBytes(Crypto.util.hexToBytes(uuidStr));
    },
    hexpad = function(n, length) {
        var str = n.toString(16);
        while (str.length < length) {
            str = '0' + str;
        }

        return str;
    },
    onFieldFinish = function(startOffset, isHeader) {
        // when a field has been written, gather up the written data for the integrity HMAC
        var endOffset = view.tell();
        var field = new PWSafeDBField(isHeader, view.getUint8(startOffset + 4), view, startOffset, view.getBytes(endOffset - startOffset - 5, startOffset + 5));
        this._updateHash(field);
        view.seek(endOffset);
    };
    var fieldStartOffset;

    types = { version: 0x00, uuid: 0x01, nonDefaultPrefs: 0x02, treeDisplayStatus: 0x03, lastSaveTime: 0x04, lastSaveApp: 0x06,
        lastSaveUser: 0x07, lastSaveHost: 0x08, recentlyUsedEntries: 0x0f };
    for (k in this.headers) {
        if (!(k in types)) {
            throw new Error('unknown header '+k);
        }

        fieldStartOffset = view.tell();

        switch(k) {
        case 'nonDefaultPrefs': case 'treeDisplayStatus': case 'lastSaveApp': case 'lastSaveUser': case 'lastSaveHost':
            writeString(this.headers[k], types[k]);
            break;
        case 'version':
            view.writeUint32(2);
            view.writeUint8(types[k]);
            view.writeUint16(this.headers.version);
            break;
        case 'uuid':
            writeUuid(this.headers.uuid, types[k]);
            break;
        case 'lastSaveTime':
            writeTimestamp(this.headers[k], types[k]);
            break;
        case 'recentlyUsedEntries':
            str = hexpad(this.headers[k].length, 2) + this.headers[k].join('');
            writeString(str, types[k]);
            break;
        default:
            throw new Error('unknown header '+k);
        }

        onFieldFinish.call(this, fieldStartOffset, true);
        this._alignToBlockBoundary(view);
    }

    // terminate headers
    view.writeUint32(0);
    view.writeUint8(0xff);
    this._alignToBlockBoundary(view);

    types = { uuid: 0x01, group: 0x02, title: 0x03, username: 0x04, notes: 0x05, password: 0x06, createTime: 0x07, passphraseModifyTime: 0x08,
        modifyTime: 0x0c, URL: 0x0d, autotype: 0x0e, passphraseHistory: 0x0f, passphrasePolicy: 0x10, emailAddress: 0x14, ownPassphraseSymbols: 0x16 };
    for (i in this.records) {
        for (k in this.records[i]) {
            if (!(k in types)) {
                throw new Error('unknown field property '+k);
            }

            fieldStartOffset = view.tell();

            switch(k) {
            case 'uuid':
                writeUuid(this.records[i][k], types[k]);
                break;
            case 'group': case 'title': case 'username': case 'notes': case 'password': case 'URL': case 'autotype':
            case 'emailAddress': case 'ownPassphraseSymbols':
                writeString(this.records[i][k], types[k]);
                break;
            case 'createTime': case 'passphraseModifyTime': case 'modifyTime':
                writeTimestamp(this.records[i][k], types[k]);
                break;
            case 'passphrasePolicy':
                var pol = this.records[i][k];
                str = hexpad(pol.flags, 4);
                var arr = [pol.length, pol.minLowercase, pol.minUppercase, pol.minDigit, pol.minSymbol];
                for (j in arr) {
                    str += hexpad(arr[j], 3);
                }
                writeString(str, types[k]);
                break;
            case 'passphraseHistory':
                var hist = this.records[i][k];
                // I tried building a string and then writing it with the writeString helper, but I think the leading 0/1 byte gets encoded by UTF-8, so
                // it's easiest to just do it all by hand here.

                view.seek(view.tell() + 4); // placeholder for size
                view.writeUint8(types[k]);
                var startPos = view.tell();
                view.writeUint8(hist.isEnabled ? 1 : 0);
                view.writeBinaryString(hexpad(hist.maxSize, 2));
                view.writeBinaryString(hexpad(hist.currentSize, 2));
                var bytes;
                for (j in hist.passphrases) {
                    var pass = hist.passphrases[j];
                    view.writeBinaryString(hexpad(pass.timestamp.getTime() / 1000, 8));
                    bytes = Crypto.charenc.UTF8.stringToBytes(pass.passphrase);
                    view.writeBinaryString(hexpad(bytes.length, 4));
                    view.writeBytes(bytes);
                }

                // go back and write size
                var endPos = view.tell();
                view.seek(startPos - 5);
                view.writeUint32(endPos - startPos);
                view.seek(endPos);
                break;
            default:
                throw new Error('unknown field property '+k);
            }

            onFieldFinish.call(this, fieldStartOffset, false);
            this._alignToBlockBoundary(view);
        }

        // terminate record
        view.writeUint32(0);
        view.writeUint8(0xff);
        this._alignToBlockBoundary(view);
    }

    // pad out the last block alignment
    view.buffer[view.tell()-1] = 0;
    return view.buffer;
},

encrypt: function(passphrase, iterations) {
    if (!iterations || iterations < PWSafeDB.MIN_HASH_ITERATIONS) {
        iterations = PWSafeDB.MIN_HASH_ITERATIONS;
    }

    var fieldsBuffer = this._serializeFields();
    var view = this._newjDataView(fieldsBuffer.length + 200);// 4 + 32 + 4 + 32 + 32 + 32 + 16 + fieldsBuffer.length + 16 + 32);

    view.writeBinaryString('PWS3');
    var salt = Crypto.util.randomBytes(32);
    view.writeBytes(salt);
    view.writeUint32(iterations);
    var stretchedPassphrase = this._stretchPassphrase(passphrase, salt, iterations);
    view.writeBytes(Crypto.SHA256(stretchedPassphrase, {asBytes: true}));

    // create, encrypt, and write master key and HMAC value
    var keys = { K: Crypto.util.randomBytes(32), L: Crypto.util.randomBytes(32) };
    view.writeBytes(TwoFish.encrypt(this._newjDataView(keys.K.concat(keys.L)), 4, stretchedPassphrase));

    // encrypt fields with a random IV, write it all out
    var IV = Crypto.util.randomBytes(PWSafeDB.BLOCK_SIZE);
    view.writeBytes(TwoFish.encrypt(this._newjDataView(IV.concat(fieldsBuffer)), (fieldsBuffer.length / PWSafeDB.BLOCK_SIZE)+1, keys.K, true));

    // trailing data
    view.writeBinaryString('PWS3-EOFPWS3-EOF');
    view.writeBytes(Crypto.HMAC(Crypto.SHA256, this._hashBytes, keys.L, {asBytes: true}));

    if (view.tell() != view.byteLength) {
        throw new Error('incorrectly calculated buffer length ('+view.tell()+', '+view.byteLength+')');
    }

    return view.buffer;
},

encryptAndSaveFile: function(passphrase, fileName, iterations) {
    if (!PWSafeDB.isNode) {
        throw new Error('saving files not supported in browser');
    }

    var buffer = this.encrypt(passphrase, iterations);
    fs.writeFileSync(fileName, buffer, { mode: 384 /* 0600 - lint complains about using octal */ });
}

});



function PWSafeDBField(isHeader, type, view, offset, bytes) {
    this.isHeader = isHeader;
    this.type = type;
    this.view = view;
    this.offset = offset;
    this.bytes = bytes;
}

PWSafeDB.extend(PWSafeDBField.prototype, {
    readStr: function() {
        try {
            return Crypto.charenc.UTF8.bytesToString(this.bytes);
        } catch (e) {
            if (e.constructor == URIError) {
                throw new Error("Invalid UTF-8 encoding", e);
            }
            throw e;
        }
    },
    readUint16: function() {
        var prevOffset = this.view.tell();
        var n = this.view.getUint16(this.offset);
        this.view.seek(prevOffset);
        return n;
    },
    readUint32: function() {
        var prevOffset = this.view.tell();
        var n = this.view.getUint32(this.offset);
        this.view.seek(prevOffset);
        return n;
    },
    readEpochTime: function() { return new Date(this.readUint32() * 1000); },
    readUuid: function() { return Crypto.util.bytesToHex(this.bytes); }
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
                postMessage({type: "PWSafeDB", records: result.records, headers: result.headers});
            }
        };

        try {
            new PWSafeDB().decrypt(data.buffer, data.passphrase, data.options, callback);
        } catch (e) {
            callback(e); return;
        }
    };
}

exports.PWSafeDB = PWSafeDB;
exports.PWSafeDBField = PWSafeDBField;

})(typeof module !== 'undefined' ? module.exports : this, this);

if (typeof module !== 'undefined') { // node.js
    var jDataView = require('./jDataView/src/jdataview.js'),
        TwoFish = require('./twofish.js'),
        Crypto = require('./crypto-sha256-hmac.js');
}
