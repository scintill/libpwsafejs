function PWSafeDB(buffer) {
    if (((typeof ArrayBuffer !== 'undefined') && (buffer instanceof ArrayBuffer)) || typeof buffer == 'string') {
        this.buffer = buffer;
    } else if (buffer instanceof Object) {
        // allow "casting" after de-JSON from the worker
        this.records = buffer.records;
    }
}


// am I a web worker?
PWSafeDB.isWebWorker = typeof importScripts != 'undefined';

PWSafeDB.downloadAndDecrypt = function(url, key, callback, forceNoWorker) {
    var useWebWorker = !forceNoWorker && window.Worker;

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


PWSafeDB.prototype.BLOCK_SIZE = 16;

PWSafeDB.prototype.decrypt = function(passphrase, callback) {
    this.view = new jDataView(this.buffer, undefined, undefined, true /* little-endian */);

    this.chunkWork(function() {

        var valid = this.validateFile();
        if (typeof valid == "string") {
            callback(valid);
            return; // <----
        }

        var keys = this.getDecryptionKeys(passphrase);
        if (typeof keys == "string") {
            callback(keys);
            return; // <----
        }

        var recordView = this.decryptRecords(keys);
        if (typeof recordView == "string") {
            callback(recordView);
            return; // <----
        }

        this.chunkWork(function() {

            this.readAllRecords(recordView);

            this.chunkWork(function() {

                this.verifyHMAC(keys, (function(pdb) { return function(matched) {
                    // clean up raw data -- some of it won't be passable through worker interface, and there's no need for it anyway
                    try {
                        delete pdb.buffer;
                        delete pdb.eofMarkerPos;
                        delete pdb.isHashing;
                        delete pdb.view;
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

PWSafeDB.prototype.validateFile = function() {
    if (this.getString(this.view, 4) != "PWS3") {
        return "Not a PWS v3 file";
    }

    this.eofMarkerPos = this.view.byteLength - 32 - this.BLOCK_SIZE;

    var eofMarker = null;
    if (this.eofMarkerPos > 0) {
        eofMarker = this.getString(this.view, this.BLOCK_SIZE, this.eofMarkerPos);
    }

    if (eofMarker != "PWS3-EOFPWS3-EOF") {
        return "No EOF marker found - not a valid v3 file, or it's corrupted";
    }

    return true;
};

PWSafeDB.prototype.decryptRecords = function(keys) {
    if (((this.eofMarkerPos - this.view.tell()) % this.BLOCK_SIZE) != 0) {
        return "EOF marker not aligned on block boundary?";
    }
    var numRecordBlocks = (this.eofMarkerPos - this.view.tell()) / this.BLOCK_SIZE;
    
    return this.dataViewFromPlaintext(TwoFish.decrypt(this.view, numRecordBlocks, keys.K, true));
};

PWSafeDB.prototype.readAllRecords = function(recordView) {
    // prepare the hash of plaintext fields
    this.isHashing = false;
    this.hashBytes = [];

    // read all fields
    this.parseHeaders(recordView);
    this.records = this.parseRecords(recordView);
};

PWSafeDB.prototype.verifyHMAC = function(keys, callback) {
    // check hash of plaintext fields
    this.view.seek(this.eofMarkerPos+this.BLOCK_SIZE);
    var expectedHMAC = this.getHexStringFromBytes(this.view, 32);

    if (PWSafeDB.isWebWorker) {
        var actualHMAC = Crypto.HMAC(Crypto.SHA256, this.hashBytes, keys.L, {asHex: true});
        callback(expectedHMAC === actualHMAC);
    } else {
        Crypto.HMAC(Crypto.SHA256, this.hashBytes, keys.L, {asHex: true, callback: function(actualHMAC) {
            callback(expectedHMAC === actualHMAC);
        }});
    }
};

PWSafeDB.prototype.getDecryptionKeys = function(passphrase) {
    // validate password and stretch it to get the decryption key
    var salt = this.getByteArray(this.view, 32, 4);
    var iter = this.view.getUint32();
    var expectedStretchedKeyHash = this.getHexStringFromBytes(this.view, 32);
    var stretchedKey = this.stretchKeySHA256(
            Crypto.charenc.Binary.stringToBytes(passphrase), salt, iter);
    var stretchedKeyHash = Crypto.SHA256(stretchedKey);

    if (expectedStretchedKeyHash !== stretchedKeyHash) {
        return "Incorrect password";
    }

    var keyView = this.dataViewFromPlaintext(TwoFish.decrypt(this.view, 4, stretchedKey));
    var keys = {};
    keys.K = this.getByteArray(keyView, 32);
    keys.L = this.getByteArray(keyView, 32);

    return keys;
};

PWSafeDB.prototype.sortRecordsByTitle = function() {
    this.records = this.records.sort(function(a, b) {
        return a.title.toLocaleLowerCase().localeCompare(b.title.toLocaleLowerCase());
    });
};

PWSafeDB.prototype.parseHeaders = function(recordView) {
    var field = undefined;
    while(field === undefined || field.type != 0xff) {
        if (recordView.tell() >= recordView.byteLength) {
            break; // <-----
        }

        var field = this.readField(recordView, true);
        switch(field.type) {
        case 0xff: // END
            break;
        default: // unknown or unimportant
            // updateHash handles all I care about for the version number record -- that is, where it is, for the HMAC verify
        }
    }
};

PWSafeDB.prototype.parseRecords = function(recordView) {
    var currentRecord = {};
    var records = [];
    while (recordView.tell() < recordView.byteLength) {
        var field = this.readField(recordView);
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

PWSafeDB.prototype.readField = function(view, isHeader) {
    isHeader = !!isHeader; // boolify undefined into false

    var fieldSize = view.getUint32();
    var field = {
        isHeader: isHeader,
        type: view.getUint8()
    };
    var bytes = this.getByteArray(view, fieldSize);
    // TODO figure out best way to handle non-string fields?
    field.valueStr = Crypto.charenc.Binary.bytesToString(bytes);
    this.updateHash(bytes, field);

    this.alignToBlockBoundary(view);

    return field;
};

PWSafeDB.prototype.dataViewFromPlaintext = function(buffer) {
    return new jDataView(jDataView.createBuffer(buffer), undefined, undefined, true /* little-endian */);
};

PWSafeDB.prototype.alignToBlockBoundary = function(view) {
    var off = view.tell() % this.BLOCK_SIZE;
    if (off) {
        view.seek(view.tell() + this.BLOCK_SIZE - off);
    }
};

PWSafeDB.prototype.stretchKeySHA256 = function(key, salt, iter) {
    key = key.concat(salt);
    for (var i = iter; i >= 0; i--) {
        key = Crypto.SHA256(key, {asBytes: true });
    }
    return key;
};

PWSafeDB.prototype.getHexStringFromBytes = function(view, byteCount) {
    return Crypto.util.bytesToHex(this.getByteArray(view, byteCount));
};

PWSafeDB.prototype.getByteArray = function(view, byteCount, offset) {
    if (offset !== undefined) {
        view.seek(offset);
    }
    var bytes = new Array(byteCount);
    for(var i = 0; i < byteCount; i++) {
        bytes[i] = view.getUint8();
    }
    return bytes;
};

PWSafeDB.prototype.getString = function(view, length, offset) {
    var bytes = this.getByteArray(view, length, offset);
    return Crypto.charenc.Binary.bytesToString(bytes);
};

PWSafeDB.prototype.updateHash = function(bytes, field) {
    if (field.isHeader && field.type == 0x00) {
        this.isHashing = true;
    }

    if (this.isHashing) {
        this.hashBytes = this.hashBytes.concat(bytes);                 
    }
};

PWSafeDB.prototype.chunkWork = function(chunkFunc) {
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
