if (typeof window === 'undefined') { // node.js
    var PWSafeDB = require('../../pwsafedb.js').PWSafeDB;
}

describe('Password Safe Database reader', function() {
    var forceNoWorkerVals = [false];
    if (typeof window != 'undefined' && window.Worker) {
        forceNoWorkerVals.push(true);
    }

    for (var forceNoWorkerI in forceNoWorkerVals) {
        var forceNoWorker = forceNoWorkerVals[forceNoWorkerI];
        var appendString = forceNoWorker ? ' without Worker' : '';
        var pdb = null, err = null;

        it('decrypts and parses the database records'+appendString, function() {
            runs(function() {
                PWSafeDB.decryptFromUrl('test.psafe3', 'pass', {forceNoWorker: forceNoWorker}, function(_pdb) { pdb = _pdb; });
            });
            waitsFor(function() { return pdb !== null; }, 'database to load', 1000);
            runs(function() {
                if (pdb instanceof Error) {
                    throw pdb;
                }

                var recs = {};
                for (var i = 0; i < pdb.records.length; i++) {
                    recs[pdb.records[i].title] = pdb.records[i];
                }

                expect(recs.length).toEqual(testRecordData.length);
                for (var k in testRecordData) {
                    expect(recs[k]).toNotEqual(undefined, 'record '+k+' exists');
                    delete recs[k].createTime;
                    delete recs[k].modifyTime;
                    delete recs[k].uuid; // don't compare these
                    expect(recs[k]).toEqual(testRecordData[k]);
                }
            });
        });

        it('reports incorrect password'+appendString, function() {
            runs(function() {
                err = null;
                PWSafeDB.decryptFromUrl('test.psafe3', 'boguspass', {forceNoWorker: forceNoWorker}, function(_err) { err = _err; });
            });
            waitsFor(function() { return err !== null; }, 'database to load', 1000);
            runs(function() {
                expect(err.message).toEqual('Incorrect passphrase');
            });
        });

        it('reports mismatched HMAC (HMAC corrupt)'+appendString, function() {
            runs(function() {
                err = null;
                PWSafeDB.decryptFromUrl('test-corrupthmac.psafe3', 'pass', {forceNoWorker: forceNoWorker}, function(_err) { err = _err; });
            });
            waitsFor(function() { return err !== null; }, 'database to load', 1000);
            runs(function() {
                expect(err.message).toEqual("HMAC didn't match -- something may be corrupted");
            });
        });

        // TODO took me a few tries to corrupt something that yielded this error. thankfully nothing like
        // infinite loops happened, but maybe I should test graceful recovery from more corruption scenarios
        it('reports mismatched HMAC (MAC corrupt)'+appendString, function() {
            runs(function() {
                err = null;
                PWSafeDB.decryptFromUrl('test-corruptdata.psafe3', 'pass', {forceNoWorker: forceNoWorker}, function(_err) { err = _err; });
            });
            waitsFor(function() { return err !== null; }, 'database to load', 1000);
            runs(function() {
                expect(err.message).toEqual("HMAC didn't match -- something may be corrupted");
            });
        });
    }
});

describe('Password Safe Database writer', function() {
    var checkRecords = function(db2, pdb) {
        if (db2 instanceof Error) {
            throw db2;
        }

        expect(db2.headers.length).toEqual(pdb.headers.length);
        var i, k;
        for (k in db2.headers) {
            expect(db2.headers[k]).toEqual(pdb.headers[k], 'header "'+k+'" is equal');
        }

        expect(db2.records.length).toEqual(pdb.records.length);
        for (i in db2.records) {
            for (k in db2.records[i]) {
                expect(db2.records[i][k]).toEqual(pdb.records[i][k], 'record ['+i+'].'+k+' is equal');
            }
        }
    };

    it('can load-reserialize-encrypt-read without loss', function() {
        var pdb = null;
        var url = 'test.psafe3';
        var pass = 'pass';

        runs(function() {
            PWSafeDB.decryptFromUrl(url, pass, {strictFieldTypeCheck: true}, function(_pdb) { pdb = _pdb; });
        });

        waitsFor(function() { return pdb !== null; }, "database to load", 1000);

        runs(function() {
            if (pdb instanceof Error) {
                throw pdb;
            }

            var db2 = null;

            runs(function() {
                new PWSafeDB().decrypt(pdb.encrypt(pass), pass, {strictFieldTypeCheck: true}, function(db) { db2 = db; });
            });

            waitsFor(function() { return db2 !== null; }, 'database to decrypt', 1000);

            runs(function() { checkRecords(db2, pdb); });
        });
    });

    if (PWSafeDB.isNode) {
        it('can write and then read a file', function() {
            var pdb = null, db2 = null;

            runs(function() {
                PWSafeDB.decryptFromUrl('test.psafe3', 'pass', {}, function(_pdb) { pdb = _pdb; });
            });
            waitsFor(function() { return pdb !== null; }, 1000, 'load database');

            runs(function() {
                pdb.encryptAndSaveFile('savepass', 'tmp.psafe3');
                PWSafeDB.decryptFromUrl('tmp.psafe3', 'savepass', {}, function(_db2) { db2 = _db2; });
            });
            waitsFor(function() { return db2 !== null; }, 1000, 'load saved database');

            runs(function() {
                require('fs').unlink('tmp.psafe3');
                checkRecords(db2, pdb);
            });
        });
    }
});
