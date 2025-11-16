"use strict";

/********* External Imports ********/

const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } = require("./lib");
const { subtle } = require('crypto').webcrypto;

/********* Constants ********/

const PBKDF2_ITERATIONS = 100000; // number of iterations for PBKDF2 algorithm
const MAX_PASSWORD_LENGTH = 64;   // we can assume no password is longer than this many characters

/********* Implementation ********/
class Keychain {
  /**
   * Initializes the keychain using the provided information. Note that external
   * users should likely never invoke the constructor directly and instead use
   * either Keychain.init or Keychain.load.
   * Arguments:
   *  You may design the constructor with any parameters you would like.
   * Return Type: void
   */
  constructor(publicData = {}, secretData = {}) {
    // Store member variables that you intend to be public here
    this.data = publicData;
    // Store member variables that you intend to be private here
    this.secrets = secretData;
  }

  /**
    * Creates an empty keychain with the given password.
    *
    * Arguments:
    *   password: string
    * Return Type: void
    */
  static async init(password) {
    const salt = getRandomBytes(16);
    const passwordBuffer = stringToBuffer(password);
    const keyMaterial = await subtle.importKey(
      "raw", passwordBuffer, { name: "PBKDF2" }, false, ["deriveKey"]
    );
    const key = await subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256"
      },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );

    const passwordDB = {};

    const publicData = {
      created: Date.now()
      // Add more metadata if needed
    };

    const secretData = {
      salt: encodeBuffer(salt), // Store salt as a string
      key: key,                 // Store the derived key
      passwordDB: passwordDB    // Store the empty password database
    };

    return new Keychain(publicData, secretData );
  }

  /**
    * Loads the keychain state from the provided representation (repr). The
    * repr variable will contain a JSON encoded serialization of the contents
    * of the KVS (as returned by the dump function). The trustedDataCheck
    * is an *optional* SHA-256 checksum that can be used to validate the
    * integrity of the contents of the KVS. If the checksum is provided and the
    * integrity check fails, an exception should be thrown. You can assume that
    * the representation passed to load is well-formed (i.e., it will be
    * a valid JSON object).Returns a Keychain object that contains the data
    * from repr.
    *
    * Arguments:
    *   password:           string
    *   repr:               string
    *   trustedDataCheck: string
    * Return Type: Keychain
    */
  static async load(password, repr, trustedDataCheck) {
    //parse the representation repr to get stored data
    const parsed = JSON.parse(repr);
    const publicData = parsed.publicData || {};
    const kvs = parsed.kvs || {};
    const salt = parsed.salt || (parsed.secretData && parsed.secretData.salt);

    // if trustedDataCheck is provided, verify the SHA-256 checksum
    if (trustedDataCheck) {
      // compute SHA-256 checksum of repr
      const encoder = new TextEncoder();
      const data = encoder.encode(repr);
      const hashBuffer = await subtle.digest('SHA-256', data);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
      if (hashHex !== trustedDataCheck) {
        throw new Error('integrity check failed: checksum does not match');
      }
    }

    // Reconstruct secretData from kvs
    const secretData = {
      salt: salt,
      passwordDB: kvs
    };

    //derive key from password and stored salt
    const saltBuffer = decodeBuffer(secretData.salt);
    const passwordBuffer = stringToBuffer(password);
    const keyMaterial = await subtle.importKey(
      "raw", passwordBuffer, { name: "PBKDF2" }, false, ["deriveKey"]
    );
    const key = await subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: saltBuffer,
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256"
      },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );

    //assign the derived key to secretData
    secretData.key = key;

    // Verify password is correct by attempting to decrypt a test entry
    // If there are passwords in the database, try to decrypt one to verify the key is correct
    if (secretData.passwordDB && Object.keys(secretData.passwordDB).length > 0) {
      try {
        // Get the first password entry
        const firstEntry = secretData.passwordDB[Object.keys(secretData.passwordDB)[0]];
        const iv = decodeBuffer(firstEntry.iv);
        const ciphertext = decodeBuffer(firstEntry.ciphertext);
        
        // Try to decrypt - this will fail if the password/key is wrong
        await subtle.decrypt(
          {
            name: "AES-GCM",
            iv: iv
          },
          key,
          ciphertext
        );
      } catch (err) {
        // Decryption failed - wrong password, throw error
        throw new Error('incorrect password');
      }
    }

    //return a new Keychain object
    return new Keychain(publicData, secretData);
  };

  /**
    * Returns a JSON serialization of the contents of the keychain that can be
    * loaded back using the load function. The return value should consist of
    * an array of two strings:
    *   arr[0] = JSON encoding of password manager
    *   arr[1] = SHA-256 checksum (as a string)
    * As discussed in the handout, the first element of the array should contain
    * all of the data in the password manager. The second element is a SHA-256
    * checksum computed over the password manager to preserve integrity.
    *
    * Return Type: array
    */
  async dump() {
    // Prepare the object to serialize
    // The kvs object should contain all password entries flattened
    // Keep salt separate so the test counts only the password entries
    const kvsObj = {};

    // Add all password entries to kvs (excluding salt, which we handle separately)
    for (const [key, value] of Object.entries(this.secrets.passwordDB)) {
      kvsObj[key] = value;
    }

    const obj = {
      publicData: this.data,
      kvs: kvsObj,
      salt: this.secrets.salt  // Store salt at root level, not in kvs
    };

    const jsonStr = JSON.stringify(obj);

    // Compute SHA-256 checksum
    const encoder = new TextEncoder();
    const data = encoder.encode(jsonStr);
    const hashBuffer = await subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

    // Return [serialized data, checksum]
    return [jsonStr, hashHex];
  };

  /**
    * Fetches the data (as a string) corresponding to the given domain from the KVS.
    * If there is no entry in the KVS that matches the given domain, then return
    * null.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<string>
    */
  async get(name) {
    // Hash the name to encrypt domain names
    const nameHash = await this._hashName(name);

    // Check if the hashed name exists in the password database
    if (!(nameHash in this.secrets.passwordDB)) {
      return null;
    }

    // Retrieve the encrypted data for this hashed name
    const encryptedData = this.secrets.passwordDB[nameHash];

    // Extract IV (initialization vector) and ciphertext from the stored data
    const iv = decodeBuffer(encryptedData.iv);
    const ciphertext = decodeBuffer(encryptedData.ciphertext);

    // Decrypt the password using AES-GCM
    const decryptedBuffer = await subtle.decrypt(
      {
        name: "AES-GCM",
        iv: iv
      },
      this.secrets.key,
      ciphertext
    );

    // Convert the decrypted buffer back to a string and return
    return bufferToString(decryptedBuffer);
  };

  /**
  * Inserts the domain and associated data into the KVS. If the domain is
  * already in the password manager, this method should update its value. If
  * not, create a new entry in the password manager.
  *
  * Arguments:
  *   name: string
  *   value: string
  * Return Type: void
  */
  async set(name, value) {
    // Hash the name to encrypt domain names
    const nameHash = await this._hashName(name);

    // Generate a random IV (initialization vector) for this encryption
    const iv = getRandomBytes(12);

    // Convert the password value to a buffer
    const passwordBuffer = stringToBuffer(value);

    // Encrypt the password using AES-GCM
    const ciphertext = await subtle.encrypt(
      {
        name: "AES-GCM",
        iv: iv
      },
      this.secrets.key,
      passwordBuffer
    );

    // Store the encrypted data (IV + ciphertext) in the password database using hashed name
    this.secrets.passwordDB[nameHash] = {
      iv: encodeBuffer(iv),           // Store IV as encoded string
      ciphertext: encodeBuffer(ciphertext)  // Store ciphertext as encoded string
    };
  };

  /**
    * Removes the record with name from the password manager. Returns true
    * if the record with the specified name is removed, false otherwise.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<boolean>
  */
  async remove(name) {
    // Hash the name to encrypt domain names
    const nameHash = await this._hashName(name);

    // Check if the hashed name exists in the password database
    if (!(nameHash in this.secrets.passwordDB)) {
      return false;  // Entry doesn't exist, return false
    }

    // Delete the entry from the password database
    delete this.secrets.passwordDB[nameHash];

    // Return true to indicate successful removal
    return true;
  };

  /**
   * Helper function to hash domain names for privacy.
   * Uses SHA-256 to create a consistent hash of the domain name.
   * This way, domain names are not stored in plain text.
   *
   * Arguments:
   *   name: string (domain name)
   * Return Type: Promise<string> (hex encoded hash)
   */
  async _hashName(name) {
    const encoder = new TextEncoder();
    const data = encoder.encode(name);
    const hashBuffer = await subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return hashHex;
  };
};

module.exports = { Keychain }
