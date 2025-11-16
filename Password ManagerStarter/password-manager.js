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
    const secretData = parsed.secretData || {};

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

    //derive key from password and stored salt
    const salt = decodeBuffer(secretData.salt);
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

    //assign the derived key to secretData
    secretData.key = key;

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
    const obj = {
      publicData: this.data,
      secretData: {
        ...this.secrets,
        // Do not include the key object itself in the dump
        key: undefined
      }
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
    throw "Not Implemented!";
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
    throw "Not Implemented!";
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
    throw "Not Implemented!";
  };
};

module.exports = { Keychain }
