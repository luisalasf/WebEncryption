
async function generateKeyPair(){
    const keyPair = await window.crypto.subtle.generateKey(
      {
        name: "ECDH",
        namedCurve: "P-384",
      },
      true,
      ["deriveKey", "deriveBits"]
    );
  
    const publicKeyJwk = await window.crypto.subtle.exportKey(
      "jwk",
      keyPair.publicKey
    );
  
    const privateKeyJwk = await window.crypto.subtle.exportKey(
      "jwk",
      keyPair.privateKey
    );
  
    return { publicKeyJwk, privateKeyJwk };
};

async function deriveKey(publicKeyJwk, privateKeyJwk) {
    const publicKey = await window.crypto.subtle.importKey(
      "jwk",
      publicKeyJwk,
      {
        name: "ECDH",
        namedCurve: "P-384",
      },
      true,
      []
    );
  
    const privateKey = await window.crypto.subtle.importKey(
      "jwk",
      privateKeyJwk,
      {
        name: "ECDH",
        namedCurve: "P-384",
      },
      true,
      ["deriveKey", "deriveBits"]
    );
  
    return await window.crypto.subtle.deriveKey(
      { name: "ECDH", public: publicKey },
      privateKey,
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );
};

const hexToUintArray = hex => {
    const a = [];
    for (let i = 0, len = hex.length; i < len; i += 2) {
      a.push(parseInt(hex.substr(i, 2), 16));
    }
    return new Uint8Array(a);
}
  
const hexToArrayBuf = hex => {
    return hexToUintArray(hex).buffer;
}
  
const arrayBufToBase64UrlEncode = bytes => {
    let binary = '';
    //const bytes = new Uint8Array(buf);
    for (var i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary)
      .replace(/\//g, '_')
      .replace(/=/g, '')
      .replace(/\+/g, '-');
}
  
const jwkConv = (pubBack) => ({
    kty: "EC",
    crv: "P-384",
    x: arrayBufToBase64UrlEncode(pubBack.slice( 1, pubBack.length/2+1)),
    y: arrayBufToBase64UrlEncode(pubBack.slice(pubBack.length/2+1, (pubBack.length/2+1)*2))
});

const  importedPublicKey = async (publicKeyBack) =>{ await crypto.subtle.importKey(
    'jwk',
    jwkConv(publicKeyBack),
    {
      name: 'ECDH',
      namedCurve: 'P-384'
    },
    true,
    []
  )};

  function parsePem(pem) {
  var typ;
  var pub;
  var crv;
  var der = pem.split('\n').filter(line => !line.startsWith("--")).join("");
  return { typ: "EC", pub: true, der: der, crv: "P-384" };
}

function toHex(ab) {
  var hex = [];
  var u8 = new Uint8Array(ab);
  var size = u8.byteLength;
  var i;
  var h;
  for (i = 0; i < size; i += 1) {
    h = u8[i].toString(16);
    if (2 === h.length) {
      hex.push(h);
    } else {
      hex.push('0' + h);
    }
  }
  return hex.join('').replace(/\s+/g, '').toLowerCase();
}

var PEM = {};
PEM._toUrlSafeBase64 = function (u8) {
  console.log('Len:', u8.byteLength);
  return u8.toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
};
// secp384r1 (SECG (Certicom) named elliptic curve)
var OBJ_ID_EC_384 = '06 05 2B81040022'.replace(/\s+/g, '').toLowerCase();

function parseEcPub(u8, jwk) {
  
  let ci = 16 + OBJ_ID_EC_384.length/2;
  let len = 48;

  var c = u8[ci];
  var xi = ci + 1;
  var x = u8.slice(xi, xi + len);
  var yi = xi + len;
  var y;
  console.log(c)
  if (0x04 === c) {
    y = u8.slice(yi, yi + len);
  } else if (0x02 !== c) {
    throw new Error("not a supported EC private key");
  }
  console.log("x: ", x);
  console.log("y: ", y);
  return {
    kty: jwk.kty
  , crv: jwk.crv
  , x: PEM._toUrlSafeBase64(x)
  //, xh: x
  , y: PEM._toUrlSafeBase64(y)
  //, yh: y
  };
}

function parseEcOnlyPrivkey(u8, jwk) {
 let olen = OBJ_ID_EC_384.length/2;
 let index = 8;
 let len = 48;
  console.log(u8);
  console.log(u8[index - 1]);
 if (len !== u8[index - 1]) {
    throw new Error("Unexpected bitlength " + len);
  }

  // private part is d
  var d = u8.slice(index, index + len);
  // compression bit index
  var ci = index + len + 2 + olen + 2 + 3;
  var c = u8[ci];
  var x, y;

  if (0x04 === c) {
    y = u8.slice(ci + 1 + len, ci + 1 + len + len);
  } else if (0x02 !== c) {
    throw new Error("not a supported EC private key");
  }
  x = u8.slice(ci + 1, ci + 1 + len);

  return {
    kty: jwk.kty
  , crv: jwk.crv
  , d: PEM._toUrlSafeBase64(d)
  //, dh: d
  , x: PEM._toUrlSafeBase64(x)
  //, xh: x
  , y: PEM._toUrlSafeBase64(y)
  //, yh: y
  };
}

const BotonGenerar = document.getElementById("GenerarKey");
var parDeLlaves = {};
BotonGenerar.addEventListener("click", async function (){
    parDeLlaves = await generateKeyPair();
    const mostrarParDeLlaves = document.getElementById("Llave");
    mostrarParDeLlaves.innerHTML = JSON.stringify(parDeLlaves);
});

const BotonDerive = document.getElementById("butDerived");
var publicKeyBack = {};

BotonDerive.addEventListener("click", function(){
    let pem = document.getElementById("PubKBack").value;
    let b64 = pem.split('\n').filter(line => !line.startsWith("--")).join("");
    //var u8 = parsePem(pem).der;
    var jwk = { kty: 'EC', crv: "P-384", x: null, y: null };
    let u8 = new Uint8Array([...atob(pem)].map(c => c.charCodeAt(0)));
    console.log(u8);
    console.log(pem);
    publicKeyBack = parseEcPub(u8, jwk)
    console.log(publicKeyBack);  
    let mostrarPublicKeyBack = document.getElementById("mostrarPBK");

    mostrarPublicKeyBack.innerHTML = JSON.stringify(publicKeyBack);


    // Parse PEM base64 format into binary bytes.
    // The first line removes comments and newlines to form one continuous
    // base64 string, the second line decodes that to a Uint8Array.
    //let b64 = pem.split('\n').filter(line => !line.startsWith("--")).join("");
    //console.log(b64);
    //let bytes = new Uint8Array([...atob(pem)].map(c => c.charCodeAt(0)));
    //mostrarPublicKeyBack.innerHTML = b64;
});