describe('Password Safe Database Reader', function() {

    // just whose idea was it to put all this hard-to-encode garbage in a test database? (mine)
    var expRecords = [
"8h3HnTwDXXm2ODTxBZWDIII\t96ln6lBqE8KMW\tnmqTuaT4bLP88Qa4HxCBvHEiPSBwIH30O7Ef613hxH2Y03uTMeRwAG6OATXkSoq\t0TZ(g,iEy6m}5dgzu/1]V@]69]$ZC~nE)G/SnTBfOi79)1N)BYPFrDK:,PBmHUe".split('\t'),
"k[5=QCDl:[QeDZ+Vm#nULE5/Uh\tc1:wfwoi.VNaihJTe9BRUur9\t(Fee)Eq%s<EOnE]>p:u2{eGl(!_Iq-7=b}.(2ukgry/JCH<xRQ:R]mbT.3nQY)|pY>\\ZC1N3()K<QWjG2kGw\t1sZ%".split('\t'),
",bMF913jCj#N_WoIL4,N21gNw;\t)rUQn\\80+{oFB7_6m\\l0EA;(\t9@Zy8Cyq?>xqv+AH8hK38dQc2P8<OV2?W-r2L.<idn%H2~[>B\\91zMnw_0aN1}<Ca&V#cf8V;3i1x6szZ>cg\t1%nggz#Ow}}Y6UqSQ>e@+CI>mOcwUUT}QO>ZE{(770ca^V3B;xSBQQ&JDMe62%HL7&dE>.CIOJ<+H{vmf|u{KTbbKfr]@>}a+St-;WtWD06|TFyq!j8:IE_K}5},2hp-f??qQNglwBcmUt-IBfTK]{CY?4^1,Gx)i%\\t[{J>~R%05f37#&ZP8lv=OD8J)yZHihP:[9x8c|#PFF8w4:nWUkCx|^tTVLz}WehDjkpI+>rNEw\\Uowx}Jbpr/OKoCb+U|pGwnD#E(nS;lgK#TT)kiIx_3a:MqHg0oRLknG=nQ{YS)_YVFB1,}3y8G0IXB3R/:+9<:;3t[YggZ+{?:s[c67cvbyS==.QCtJzv\\tu^bR#MhigpqKf[Gj+{hL%^<4XaWT:8q3oNWJ9#QFCx_!+fXY@@3j[,&iaepB;Eemo9b>_AeNhe)mJFY}xm(#Lndul)mbE3O3Xzt7qxX[AN/1U)\\2>u)9S[+x!>5&-2WkhIm4I:s2i}Uw++kh4Uk<h|KmizS8K[v3uF13FP]z3Qg&f_cr;~F-b9,=Ij6yS6o7YUU203Dt5vhy]KG>pK}b{&(Z#F)7uTdj5=HY~PGgKkYm9Wznk>".split('\t'),
"(&@m{K1sd3m6XY{~QB3l$rtlL%$sc)c4pn_\tbq-7jo/:5lU~P[8fGbRluTFP\t}VpNCb{(Z4FQa:N6D~~v6p5sFt]n4@0OwaiHH1tKA[ja&<l6O.kyC^)Nq8Jt!H~)ebSrHHzd->fKOG4=\\s:e\tOVwq79loGsd3%LLq^1>-OeXb9b~9E8s}p4x$}@!\\A.ZwOt$n-2pviDHt%=:4?Z!yblRH-cfDF_oF$,|4OPk>XFU&ynWyK22OLHU=<5y!aD.}9#Y.O<A?Y){?&UbpooD~,hK?yxU#pchyg;7j#%]l}XZDvP;nh~6Ocpd8KiyoEbwnI)&=iK_<#?.Qj4+1tO{..Fl0\\;b>sIw<b$knEI#QA>vs:am;/|}\\7:WDZc3&}<_BiSpDZA4TRLS9n(8XJkTR]H5K21c=q<[Am9884-gy!@]5f]GbpCJ>;rI=WIN!s|,0JkmTROTfEe:3k9ME[=SfRoLm{u:\\(_[6vjb(|WI8=5J?zRko[RGtcz5QUo{uYP#Px=<W^;bi)f^@mg\\GjIkV/ODB57.\\Rq0N|GDVWGp.%OI_^;ORh!HNBP;[^e#sO1_=wpT{)}oXIs4GOTCCBp(ExYeG!LCAhqJCF<t^lfVSziJd=#.9jj1-w!$8[2duiMfGTYyBr-9m/1q@h0\\}\\i{WyJplvOy(H%GZx/6dGw;{2EPMd[GZI{Zbl0$<oe=fzn,DS!?nG5Vx5f6i40Uue!ceiE(9,\\i785^y8Up2Wn+w~~v3".split('\t'),
"Cskphr5eH)|ha5?Vpr4m5P4D$(_lpQ+$CA>\tb+wh}1xpxDXwiYm4pg$d+;Nv\tj>peH9JV}L-VzYQS-sYST:4bfM%3>vtSr1G=#[{[w$mE^qtbAhiBI4s7Ad^\\Thy~\\Ywk%C@t:1h)Xy5evdouI2zd2c)~gl.bhMw7fP4}b#S6%vy!rDl)GB/QXU.{])TIPBSKDT!5~&HvRu=Z~]S=|#1jna#&-1,2^|9+j9;5[6t!EF\\p&jrjG(3;w\\)AT++&mw!-siHS]G,\\lhEU8&e>fnP-5M][LCDFwPM;Jm7!4}eubM4;t#Mw!z0C~plkIvAT2TdFE#ZZ^!+C:>[S&$;W/GQ=P{h$QOZ7H>8+%Zxyd[QZUTK[n:k5;/KPPddybM,1-VQ?^X/r/X|@6f{RGcx67-#l]|KtsT9//#;2#mJ9F^iSf#w\t3=X.e4B/tkX~rk]Lg!g#|Hb~E{v4,6BPu;+GYl5W/YPT\\KY|z:u:F<4uQIwaN<rWk[n0rf;q%u%b}F+f#.6I7YNo7edoAO3O?Jk:@3o)e|K4ZU-Ng3g84514=U.Zqcgu<[n=]d&<70Y_i;~LW5L\\c7l%5%~r^K-^lYxZEvg<PI+k>iy3c^S>P[QWtQzKd>P|BF1U;:x-JbUNMlkQ__ByR}m,sJCmgikb5c|O^N=Fk)+P>^GM&ee,B+aIFj[=pLB!p[]Ob-ElBLwIRn$Xm4QT/TsjO--Ry{Quv2{gwYMopr<5RH0Qsd=7DI]c%,F6QMC?C8nfT,0F^cRcZ$I7!I$L9CWgTaur+~Zd[dX_6P}2kA-(QbG;~=k]UZGe!}d=u,aO0re{IO[^l@Dy^j,?>/yI6^Gik%KH%$]Lb9C-+<-I>X?}uw>}dBsi#|%=J9sz+pTeJ.VU.vx|9Y4v=;[D{I_ZGd<FY}/9=xr@XQYqs@T:z+w&eQ$9f{0eS2Gy<L|#1Q\\}/2oICh9eqKuC1pb&Bf[5Gm1ig#5p<FUY>gDmxpq%Rnjv4DdfdQU7y6h(+.>H}\\\\Ow_j=S;Pe!~2LyDD#N_3gdw$u".split('\t'),
"IcUlF@+kw,,{;QQ8@\txqcK1=\\AS::GjFLs?|/H!vBg\tINBVma0.R2ShqXK#25Q>O~Bo%/}6;?G-#J\\zMXs9=86CZU!}@|G:b_9^&&d),.2jSF6y}mT[;M<%G!/0.:TSA7eN^pzp@luCk55]hVPtV%hw~?-(0sx>|yEjK<;1CQSI6\\z|Rbj$a6i_3p=N_AXi,H3}?m%w>:;^L:X/zV2$[ITbdH(pFWGDWZX)fxiX\\m(,7tb~,Q.3P}x]E3hz#pFOM~7NmFe)ZYhM=Xr7(GE$qG6W=E3x>P)Y:YUSlCc|ET;DF{3UuT1;rh$/yaxY.ha|rfXy0G+4aDH6~}uzt\\LA=Wb1>>dg;2ZQM>uQt(YAs8P?hX8Ou,!l:D=|S_sYt,|DiLr+6SDf2L1+w=0gOibML<(%1pj\tS}5tW7:N$\\p<qC[STk\\cAA)Ee]X.|V^Se1F+vk!Xf,RFs!}+w7&a1rI@d9,$|VE]96cGr98,Y6RI2iTZu1/{l)BA7B[\\kv<11qF!3zp?f=}$-mSX9V\\J5MU6^4%Zcq5CM_rq1zR^o}X-v@XYw0C]PCB?NzuDOCm$[59iFOr(Zc)\\[t[Ugj|]LE{z5b;gB=)@wh\\~\\4pN?2CG,.<IB~\\oV32:v?8|UVe(wknBNE<]CElsXz~%f_|ubZ;:1=:PL-jE0!=Yl|Io{NVM(i$!nEjRzDOm<[Y]vYPWQaxA/j#VsDodzJM(,W3|#m%4:NdJaJMDf^ZKLT5(iJ{&DX6jMsn>To7(hgWjka#w9Rf2MHIRQaZ=G_I0+)0zxZH]:Vok8nGMN5EC3%kO#?%tOf+Y0LHas6]El9u~Y>G3-DU9:RIb^3Hx//?XJ}a]a4_n5+d~)LY;4bjg%KHCK)oOwOWnkh:Dg8$fF}r%e82KJ1^Bh#2Av6yT6}ZQ^[95ArYPUF)i1jyNZ62/-fGW+dM=OK.iD(\\Mp$W!<_J>ZvW[5HfF<XUhmH)]GSKecZYy:@/Av1EUG%8wBQo{gLWi-\\7K1-x8E9mrhHgW".split('\t'),
"_&f|2SNfYo)hAr^te\t>uK~4\\nZ<vI\\mt/O-}Q#[|$~\twrGM[}1ZDWfQ4T>9Y]|P3#n+U&0!b)f@19>UKGW658QKmoY.T?wX(qgw&]\\y9)cL2#S|F_I,--[E$T8HEzNO-[BlV1M5!:jTBfQ08Gu)z^6|y-ua]6S/V,N<4#+Ppy~Bi5zNi<30)n9M02r:@a53m><qTW-1A=fg3m//|;+ZD}GWx0q=r]q-#Lt#q~>oniQ>5)BKDL<#o0k3y7e}lv\\67l/SRoe:NhDAT13}+}>C^M}P1:4G0=&LxrA3ti<5_#LOT,m3}~7^J[[&&>s8n!@SJr~[x2oI+/P-/ez&l:Ol-VN%|zy9g>NB|ST(YUs#(lV(5W><t.u^}{#YE;1P9)OEj6S/xg<Y0tEr$k}!C1-h#EkzPp,\t|>Acs70LHv5.(=Ug9nvk)fu^l};5Ias8\\.W=0pZWX%}COKPcxk5,:39n)JV]#<JjB4|iZ>^C~ax-p>J9$tSZ/o;:mm9Y0!Zi-VC!OyU^n;3$l#MyHDp_{rGYf$7w>W-1ZS6i$K<=(JYeVh%~=@~?+ESfDWB(:@r{cI[SDXw5Zto4f3?i_NWk/K,rpiIr}c;kw.3:J}Lr)Pr/:[izSZ%<7a3!$_q+h5BpIx8{p}T}L2k~=~h5HCPs9rqGB(?\\MO[J;>lQR8YI/ff1~AqjK;}:D3[DT}Qrohyr/IY@w<j@z!jU.>|6L]W<CLwGxlShG&eY/.bZ:a,z1.U..NixRy&<]GrgwpRFv.R6EJn=by{/|tdu|G=)d]R$sof2UE>+#PC(7z\\#1mn.L@gDrt!u[D>0PqCM|-^f{p[n4oWu<,XXp>87,rxP23OAfNpSgyxnvyd$_pZifN&(3d#?AsI:i;]<_O^Gi<8_]WkQfh&pxQaXq|^7:1D8x0%~8K)(;4mlywvH7TeGdlk!>Vvt+-XHtS=L[E;zZZ--E+(G01!n$a-Tp_y#FZPF+VC/>cWk|f<[{OK_9Z,vb[CTD.eKa=1g|q/a.!\\c".split('\t'),
// UTF-8 text
["Iｎｔéｒｎâｔïｏｎäɭｉｚａｔíｏл", "test", "test", "Bäｃｏл ìｐｓüｍ ԁ߀ɭ߀ｒ ѕìｔ àｍéｔ éｉｕｓｍòᏧ ѕհòｒｔ ɭòïл ｔ߀ｎǥüｅ ûｔ ρｉｇ ｇｒòúԉᏧ ｒ߀ùｎԁ. Rｅρｒéɦêлｄêｒíｔ ｔùｒｋêϒ ｆｒãԉƙｆûｒｔéｒ âｕｔé. Eлïｍ ｔúｒｄúｃƙèｎ ｃｏлѕêｃｔêｔｕｒ, ｆúǥïãｔ ｃɦùｃｋ ｐòｒƙ ƃéɭɭｙ ｔ߀ԉɢúé. Düïｓ ｆｒåԉƙｆｕｒｔêｒ íｎ ѵëｎíｓ߀ｎ ｄèѕéｒûлｔ ɑｄ ｃｏɰ ａｌíɋûｉρ հàϻｂùｒｇëｒ èｎｉϻ ѕùԉｔ ѕíｒｌòìл òｃｃàｅｃàｔ ｖéԉíãｍ. Eɭíｔ ɦäｍ ｈòｃｋ ƅèｅｆ ｕｔ.\r\n"+
"\r\n"+
"Tèｍρ߀ｒ ｂｒｉѕｋëｔ ｓúｎｔ, ѕɦａｎƙ ƅìｌｔ߀ｎɢ ïｎｃíᏧｉｄúԉｔ ƅòûｄｉｎ ԉùɭｌɑ ｍòɭɭｉｔ ƃｒêｓâ߀ɭä ｈãϻｂûｒɢéｒ ｎｏԉ ƙｉｅɭƃàѕä ｓｔｒíρ ѕｔｅåｋ. Vｅｌｉｔ éú ｃｈûｃƙ, éѕｔ ｓρàｒè ｒïƃѕ ｍèãｔｂäｌｌ ԉｉｓí ｆｒãԉƙｆùｒｔèｒ ｔúｒԁûｃｋëл ｐɑｒìåｔúｒ ѕíｒｌòïｎ ｆüｇìáｔ èхêｒｃïｔåｔí߀ԉ. Dｒｕϻѕｔíｃｋ ｂɑｌɭ ｔìｐ ｔâìｌ, ｓｔｒíρ ｓｔèâｋ ρɑｓｔｒäϻｉ ｒìｂèϒｅ ｃòｍϻòｄò. Sìԉｔ ѕɦòｒｔ ｒïƅｓ ｄèｓｅｒüлｔ ѵｏｌüｐｔãｔê ԁòｌ߀ｒé ùɭｌàϻｃò ｕｔ ԁｏｌ߀ｒè հàｍƃùｒǥｅｒ ａüｔê ѕɦàｎｋɭë.\r\n"+
"\r\n"+
"Mｏɭｌｉｔ ｔｏԉｇüè ｃհｉｃｋêｎ, ѕｈｏｒｔ ɭ߀ｉл ｔｒï-ｔìρ èｕ Ꮷ߀ｎéｒ ϻｉԉìｍ ρòｒƙ ɭ߀ｉл ｅхｃèρｔèüｒ ƃíɭｔｏлｇ ɭàｂｏｒｅ íｎ. Hãϻｂüｒɢéｒ íｎ ｌåƅｏｒïѕ, ϻｉлíｍ ɋｕìｓ ρ߀ｒƙ ｂéɭɭϒ ｓｔｒíｐ ѕｔêàƙ. T߀ｎɢúë ѕåùｓａǥë ƅíｌｔ߀ｎｇ ƅｒｉｓƙéｔ ｒïƃｅϒê ѕｈòｒｔ ｒíｂѕ ρïǥ. Véɭｉｔ ƃｒíｓƙèｔ ѕɦòüｌｄêｒ, ｆɑｔƃａｃｋ êíùѕϻｏｄ ｓàɭãϻí ɑлíｍ ｓíԉｔ ｉл ïԉ ｔéԉԁëｒɭòｉл ｕｔ. Iԉ ùｔ íｄ, ｌåƅ߀ｒê ｔêϻρòｒ ｌéƃèｒｋáｓ ƅｉｌｔòлɢ ｔｅｎԁèｒɭｏíｎ ｖèｌｉｔ ｑùｉｓ ｒèρｒèｈèлᏧêｒïｔ ïｎ ëｔ ｃûρìᏧａｔàｔ. Uｔ ｐòｒƙ ƅèɭɭϒ ｃ߀ｎѕéｃｔèｔüｒ, ｐ߀ｒｋ ɭòïл Ꮷ߀ɭｏｒｅ ｌåƅｏｒé հäϻ ｔ-ƅｏｎê ｃｈùｃｋ ߀ｆｆíｃｉâ ԁ߀ɭｏｒë ѕհ߀ｒｔ ｌòｉԉ. Tｏлɢüé лｏѕｔｒûｄ ｓρâｒë ｒïƅｓ ｔ-ｂòԉë éхêｒｃìｔáｔìｏл."]];
    expRecords = (function() {
        for (var i = 0; i < expRecords.length; i++) {
            this[expRecords[i][0]] = {title: expRecords[i][0], username: expRecords[i][1], password: expRecords[i][2], notes: expRecords[i][3]};
        }
        return this;
    }).apply({});

    var decrypt = function(forceNoWorker, funToRun, pass, url) {
        var pdb = null;
        url = url || 'test.psafe3';
        pass = pass || 'pass';

        runs(function() {
            PWSafeDB.downloadAndDecrypt(url, pass, function(_pdb) { pdb = _pdb; }, forceNoWorker);
        });

        waitsFor(function() { return pdb !== null; }, "database to load", 3000);

        runs(function() { funToRun(pdb); });
    };

    var expectRecords = function(pdb) {
        if (pdb instanceof Error) {
            throw pdb;
        }

        var recs = {};
        for (var i = 0; i < pdb.records.length; i++) {
            recs[pdb.records[i].title] = pdb.records[i];
        }

        expect(recs.length).toEqual(expRecords.length);
        for (var k in expRecords) {
            expect(recs[k]).toNotEqual(undefined);
            delete recs[k].createTime;
            delete recs[k].modifyTime;
            delete recs[k].uuid; // don't compare these
            expect(recs[k]).toEqual(expRecords[k]);
        }
    };

    var allTests = function(workerVal, appendString) {
        it('decrypt and parse the database records'+appendString, function() { return decrypt(workerVal, expectRecords); });
        it('report incorrect password'+appendString, function() {
                return decrypt(workerVal, function(err) {
                    expect(err.message).toEqual("Incorrect passphrase");
                }, "boguspass");
        });
        it('report mismatched HMAC (HMAC corrupt)'+appendString, function() {
                return decrypt(workerVal, function(err) {
                    expect(err.message).toEqual("HMAC didn't match -- something may be corrupted");
                }, undefined, 'test-corrupthmac.psafe3');
        });
        // TODO took me a few tries to corrupt something that yielded this error. thankfully nothing like
        // infinite loops happened, but maybe I should test graceful recovery from more corruption scenarios
        it('report mismatched HMAC (MAC corrupt)'+appendString, function() {
                return decrypt(workerVal, function(err) {
                    expect(err.message).toEqual("HMAC didn't match -- something may be corrupted");
                }, undefined, 'test-corruptdata.psafe3');
        });
    };

    allTests(false, " (worker if avail)");
    if (window.Worker) {
        allTests(true, " (non-worker)");
    }

});
