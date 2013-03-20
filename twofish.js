// http://members.tele2.nl/MAvanEverdingen/Code/code.html
(function(exports) {

var tfsKey=[];
var tfsM=[[],[],[],[]];

function tfsInit(key) {
  var  i, a, b, c, d, meKey=[], moKey=[], inKey=[];
  var kLen;
  var sKey=[];
  var  f01, f5b, fef;

  var q0=[[8,1,7,13,6,15,3,2,0,11,5,9,14,12,10,4],[2,8,11,13,15,7,6,14,3,1,9,4,0,10,12,5]];
  var q1=[[14,12,11,8,1,2,3,5,15,4,10,6,7,0,9,13],[1,14,2,11,4,12,3,7,6,13,10,5,15,9,0,8]];
  var q2=[[11,10,5,14,6,13,9,0,12,8,15,3,2,4,7,1],[4,12,7,5,1,6,9,10,0,14,13,8,2,11,3,15]];
  var q3=[[13,7,15,4,1,2,6,14,9,11,3,0,8,5,12,10],[11,9,5,1,12,3,13,14,6,4,7,15,2,0,8,10]];
  var ror4=[0,8,1,9,2,10,3,11,4,12,5,13,6,14,7,15];
  var ashx=[0,9,2,11,4,13,6,15,8,1,10,3,12,5,14,7];
  var q=[[],[]];
  var m=[[],[],[],[]];

  function ffm5b(x){ return x^(x>>2)^[0,90,180,238][x&3]; }
  function ffmEf(x){ return x^(x>>1)^(x>>2)^[0,238,180,90][x&3]; }

  function mdsRem(p,q){
    var i,t,u;
    for(i=0; i<8; i++){
      t = q>>>24;
      q = ((q<<8)&wMax) | p>>>24;
      p = (p<<8)&wMax;
      u = t<<1; if (t&128){ u^=333; }
      q ^= t^(u<<16);
      u ^= t>>>1; if (t&1){ u^=166; }
      q ^= u<<24 | u<<8;
    }
    return q;
  }

  function qp(n,x){
    var a,b,c,d;
    a=x>>4; b=x&15;
    c=q0[n][a^b]; d=q1[n][ror4[b]^ashx[a]];
    return q3[n][ror4[d]^ashx[c]]<<4 | q2[n][c^d];
  }

  function hFun(x,key){
    var a=getB(x,0), b=getB(x,1), c=getB(x,2), d=getB(x,3);
    switch(kLen){
    case 4:
      a = q[1][a]^getB(key[3],0);
      b = q[0][b]^getB(key[3],1);
      c = q[0][c]^getB(key[3],2);
      d = q[1][d]^getB(key[3],3);
    case 3:
      a = q[1][a]^getB(key[2],0);
      b = q[1][b]^getB(key[2],1);
      c = q[0][c]^getB(key[2],2);
      d = q[0][d]^getB(key[2],3);
    case 2:
      a = q[0][q[0][a]^getB(key[1],0)]^getB(key[0],0);
      b = q[0][q[1][b]^getB(key[1],1)]^getB(key[0],1);
      c = q[1][q[0][c]^getB(key[1],2)]^getB(key[0],2);
      d = q[1][q[1][d]^getB(key[1],3)]^getB(key[0],3);
    }
    return m[0][a]^m[1][b]^m[2][c]^m[3][d];
  }

  key=key.slice(0,32); i=key.length;
  while ( i!=16 && i!=24 && i!=32 ) key[i++]=0;

  for (i=0; i<key.length; i+=4){ inKey[i>>2]=getW(key, i); }
  for (i=0; i<256; i++){ q[0][i]=qp(0,i); q[1][i]=qp(1,i); }
  for (i=0; i<256; i++){
    f01 = q[1][i]; f5b = ffm5b(f01); fef = ffmEf(f01);
    m[0][i] = f01 + (f5b<<8) + (fef<<16) + (fef<<24);
    m[2][i] = f5b + (fef<<8) + (f01<<16) + (fef<<24);
    f01 = q[0][i]; f5b = ffm5b(f01); fef = ffmEf(f01);
    m[1][i] = fef + (fef<<8) + (f5b<<16) + (f01<<24);
    m[3][i] = f5b + (f01<<8) + (fef<<16) + (f5b<<24);
  }

  kLen = inKey.length/2;
  for (i=0; i<kLen; i++){
    a = inKey[i+i];   meKey[i] = a;
    b = inKey[i+i+1]; moKey[i] = b;
    sKey[kLen-i-1] = mdsRem(a,b);
  }

  for (i=0; i<40; i+=2){
    a=0x1010101*i; b=a+0x1010101;
    a=hFun(a,meKey);
    b=rotw(hFun(b,moKey),8);
    tfsKey[i]=(a+b)&wMax;
    tfsKey[i+1]=rotw(a+2*b,9);
  }
  for (i=0; i<256; i++){
    a=b=c=d=i;
    switch(kLen){
    case 4:
      a = q[1][a]^getB(sKey[3],0);
      b = q[0][b]^getB(sKey[3],1);
      c = q[0][c]^getB(sKey[3],2);
      d = q[1][d]^getB(sKey[3],3);
    case 3:
      a = q[1][a]^getB(sKey[2],0);
      b = q[1][b]^getB(sKey[2],1);
      c = q[0][c]^getB(sKey[2],2);
      d = q[0][d]^getB(sKey[2],3);
    case 2:
      tfsM[0][i] = m[0][q[0][q[0][a]^getB(sKey[1],0)]^getB(sKey[0],0)];
      tfsM[1][i] = m[1][q[0][q[1][b]^getB(sKey[1],1)]^getB(sKey[0],1)];
      tfsM[2][i] = m[2][q[1][q[0][c]^getB(sKey[1],2)]^getB(sKey[0],2)];
      tfsM[3][i] = m[3][q[1][q[1][d]^getB(sKey[1],3)]^getB(sKey[0],3)];
    }
  }
}

function tfsG0(x){ return tfsM[0][getB(x,0)]^tfsM[1][getB(x,1)]^tfsM[2][getB(x,2)]^tfsM[3][getB(x,3)]; }
function tfsG1(x){ return tfsM[0][getB(x,3)]^tfsM[1][getB(x,0)]^tfsM[2][getB(x,1)]^tfsM[3][getB(x,2)]; }

function tfsFrnd(r,blk){
  var a=tfsG0(blk[0]); var b=tfsG1(blk[1]);
  blk[2] = rotw( blk[2]^(a+b+tfsKey[4*r+8])&wMax, 31 );
  blk[3] = rotw(blk[3],1) ^ (a+2*b+tfsKey[4*r+9])&wMax;
  a=tfsG0(blk[2]); b=tfsG1(blk[3]);
  blk[0] = rotw( blk[0]^(a+b+tfsKey[4*r+10])&wMax, 31 );
  blk[1] = rotw(blk[1],1) ^ (a+2*b+tfsKey[4*r+11])&wMax;
}

function tfsIrnd(i,blk){
  var a=tfsG0(blk[0]); var b=tfsG1(blk[1]);
  blk[2] = rotw(blk[2],1) ^ (a+b+tfsKey[4*i+10])&wMax;
  blk[3] = rotw( blk[3]^(a+2*b+tfsKey[4*i+11])&wMax, 31 );
  a=tfsG0(blk[2]); b=tfsG1(blk[3]);
  blk[0] = rotw(blk[0],1) ^ (a+b+tfsKey[4*i+8])&wMax;
  blk[1] = rotw( blk[1]^(a+2*b+tfsKey[4*i+9])&wMax, 31 );
}

function tfsClose(){
  tfsKey=[];
  tfsM=[[],[],[],[]];
}

function tfsEncrypt(blk) {
  blk[0] ^= tfsKey[0];
  blk[1] ^= tfsKey[1];
  blk[2] ^= tfsKey[2];
  blk[3] ^= tfsKey[3];
  for (var j=0;j<8;j++){ tfsFrnd(j,blk); }
  setW(outBuffer,outOffset   ,blk[2]^tfsKey[4]);
  setW(outBuffer,outOffset+ 4,blk[3]^tfsKey[5]);
  setW(outBuffer,outOffset+ 8,blk[0]^tfsKey[6]);
  setW(outBuffer,outOffset+12,blk[1]^tfsKey[7]);
}

function tfsDecrypt(blk) {
  blk[0] ^= tfsKey[4];
  blk[1] ^= tfsKey[5];
  blk[2] ^= tfsKey[6];
  blk[3] ^= tfsKey[7];
  for (var j=7;j>=0;j--){ tfsIrnd(j,blk); }
  setW(outBuffer,outOffset   ,blk[2]^tfsKey[0]);
  setW(outBuffer,outOffset+ 4,blk[3]^tfsKey[1]);
  setW(outBuffer,outOffset+ 8,blk[0]^tfsKey[2]);
  setW(outBuffer,outOffset+12,blk[1]^tfsKey[3]);
}

function getW(a,i){ return a[i]|a[i+1]<<8|a[i+2]<<16|a[i+3]<<24; }
function setW(a,i,w){ a.splice(i,4,w&0xFF,(w>>>8)&0xFF,(w>>>16)&0xFF,(w>>>24)&0xFF); }
function rotw(w,n){ return ( w<<n | w>>>(32-n) ) & wMax; }
function getB(x,n){ return (x>>>(n*8))&0xFF; }
wMax = 0xffffffff;

exports.BLOCK_SIZE = 16;
exports.decrypt = function(dataView, blockCount, key, cbcMode) {
    tfsInit(key);

    outBuffer = new Array(blockCount * this.BLOCK_SIZE);
    outOffset = 0;

    if (cbcMode) {
        // skip initialization vector
        dataView.seek(dataView.tell() + this.BLOCK_SIZE);
        blockCount--;
    }

    while (blockCount--) {
        var block = [dataView.getUint32(), dataView.getUint32(), dataView.getUint32(), dataView.getUint32()];

        tfsDecrypt(block);

        if (cbcMode) {
            var tell = dataView.tell();
            dataView.seek(tell - 2*this.BLOCK_SIZE);
            for (var i = 0; i < this.BLOCK_SIZE; i += 4) {
                setW(outBuffer, outOffset + i, getW(outBuffer, outOffset + i) ^ dataView.getUint32());
            }
            dataView.seek(tell);
        }

        outOffset += this.BLOCK_SIZE;
    }

    return outBuffer;
};
exports.encrypt = function(dataView, blockCount, key, cbcMode) {
    tfsInit(key);

    outBuffer = new Array(blockCount * this.BLOCK_SIZE);
    outOffset = 0;

    if (cbcMode) {
        // initialization vector
        dataView.seek(0);
        for (outOffset = 0; outOffset < this.BLOCK_SIZE; outOffset++) {
            outBuffer[outOffset] = dataView.getUint8();
        }
        blockCount--;
    }

    while (blockCount--) {
        var block = [dataView.getUint32(), dataView.getUint32(), dataView.getUint32(), dataView.getUint32()];

        if (cbcMode) {
            var tell = dataView.tell();
            dataView.seek(tell - 2*this.BLOCK_SIZE);
            for (var i = 0; i < block.length; i++) {
                block[i] ^= getW(outBuffer, outOffset - this.BLOCK_SIZE + i*4);
            }
            dataView.seek(tell);
        }

        tfsEncrypt(block);

        outOffset += this.BLOCK_SIZE;
    }

    return outBuffer;
};

})(typeof module !== 'undefined' ? module.exports : (this.TwoFish = {}));
