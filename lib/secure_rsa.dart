/// The main function where the RSA encryption and decryption process starts.
void main() {
  // Generate two distinct prime numbers for RSA algorithm.
  var primes = generateTwoDistinctPrimes();
  var p = primes[0]; // First prime number.
  var q = primes[1]; // Second prime number.

  // Calculate modulus (n) by multiplying p and q.
  var n = p * q;

  // Calculate Euler's totient function (phi) for n.
  var phi = (p - BigInt.one) * (q - BigInt.one);

  // Choose a public exponent 'e' that is coprime with phi.
  var e = chooseE(phi);

  // Calculate private key exponent 'd' which is the modular inverse of e mod phi.
  var d = e.modInverse(phi);

  // Define public key with exponents 'e' and modulus 'n'.
  var publicKey = {'e': e, 'n': n};

  // Define private key with exponents 'd' and modulus 'n'.
  var privateKey = {'d': d, 'n': n};

  // Original message that will be encrypted and decrypted.
  BigInt message = BigInt.from(2000);
  print('Original Message: $message');

  if (message >= n) {
    throw ArgumentError('Message must be smaller than (modulus - 1) (1 < message < n -1) (n = $n).');
  }

  // Encrypt the original message using the public key.
  BigInt encrypted = rsaEncrypt(message, publicKey);
  print('Encrypted Message: $encrypted');

  // Decrypt the encrypted message using the private key.
  BigInt decrypted = rsaDecrypt(encrypted, privateKey);
  print('Decrypted Message: $decrypted');
}

/// Encrypts a message with RSA public key.
BigInt rsaEncrypt(BigInt message, Map<String, BigInt> publicKey) {
  // Encrypted message is calculated as message^e mod n.
  return message.modPow(publicKey['e']!, publicKey['n']!);
}

/// Decrypts an RSA encrypted message with the private key.
BigInt rsaDecrypt(BigInt encryptedMessage, Map<String, BigInt> privateKey) {
  // Decrypted message is calculated as encryptedMessage^d mod n.
  return encryptedMessage.modPow(privateKey['d']!, privateKey['n']!);
}

/// Generates a list containing two distinct prime numbers.
List<BigInt> generateTwoDistinctPrimes() {
  return [BigInt.from(97), BigInt.from(13)];
}

/// Chooses a public exponent 'e' that is relatively prime to 'phi' (coprime).
BigInt chooseE(BigInt phi) {
  BigInt e = BigInt.from(3); // Start with a small odd integer for 'e'.

  // Increment 'e' until it is coprime with 'phi'.
  while (phi.gcd(e) > BigInt.one) {
    e = e + BigInt.two;
  }
  return e;
}
