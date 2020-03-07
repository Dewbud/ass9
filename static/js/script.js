/**
 * @param  {string} message        the thing you're encrypting
 * @param  {string} rsa_public_key the RSA public key acquired from /api/v1/public/tokenize/key
 * @return  {string}
 */
function encrypt(message, rsa_public_key) {
  // Random symmetric key
  let sym_key = forge.random.getBytesSync(32);

  $('#aes_key').val(forge.util.encode64(sym_key));
  $('#aes_key_wrapper').collapse('show');

  // Encrypt message with symmetric key
  const AES = forge.cipher.createCipher("AES-CBC", sym_key);
  const iv = sym_key.substring(0, 16); // use first 16 as iv
  AES.start({ iv });
  AES.update(forge.util.createBuffer(message));
  AES.finish();

  // Base 64 encode message cipher
  const message_cipher = forge.util.encode64(AES.output.data);

  // Encrypt the symmetric key with the asymmetric key
  const key = forge.pki.publicKeyFromPem(rsa_public_key);
  sym_key = key.encrypt(sym_key, "RSA-OAEP");

  // Base 64 encode the symmetric key
  sym_key = forge.util.encode64(sym_key);
  // Encode length of symmetric key in hex
  const len = sym_key.length.toString(16).padStart(3, "0");

  // Concatenate hex length, symmetric key and message cipher
  return `${len}${sym_key}${message_cipher}`;
}

let rsa_key = null;

async function getRsaKey() {
  if (rsa_key) {
    return rsa_key;
  }

  rsa_key = null;

  const req_opts = {
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json"
    }
  };

  const response = await fetch(`/key`, req_opts);

  if (!response.ok) {
    const error = new Error("failed to get rsa key");
    error.response = response;
    throw error;
  }

  rsa_key = await response.json();

  return rsa_key;
}

/**
 * @param {object} request
 */
async function decrypt(request) {
  const req_opts = {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json"
    },
    body: JSON.stringify(request)
  };

  const response = await fetch(`decrypt`, req_opts);

  if (!response.ok) {
    const error = new Error("tokenization failure");
    error.response = response;
    throw error;
  }

  rsa_key = null;

  return await response.json();
}

/**
 * @param {string} payload
 */
async function send(payload) {
  const rsa_key = await getRsaKey();

  $('#rsa_key').val(rsa_key.public_key);
  $('#rsa_key_wrapper').collapse('show');

  const request_body = {
    id: rsa_key.id,
    message: encrypt(payload, rsa_key.public_key)
  };

  $('#payload').val(request_body.message);
  $('#payload_wrapper').collapse('show');

  return await decrypt(request_body);
}

console.log(forge);

$('#form').submit(async (e) => {
    e.preventDefault();
    console.log('form submit');
    const message = $('#message').val();
    const response = await send(message);

    $('#response').val(response.message);
    $('#response_wrapper').collapse('show');
});

