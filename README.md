 
![swap.online transaction](https://raw.githubusercontent.com/cypherpunk99/bitcoinTx/master/swapStart.png)

Send from `mjGqLcJgCkJzHiXXNipBWVgvgVPWt49L2S` to `mpwdymxe6cCRviGDahusMtWQ3SSD6PDgbz` amount `0.00009`
Current BTC Balance: `0.13146099`

![values](https://raw.githubusercontent.com/cypherpunk99/bitcoinTx/master/values.png)

```javascript
unspents = {
  0: {
    address: "mjGqLcJgCkJzHiXXNipBWVgvgVPWt49L2S"
    amount: 0.13146099
    confirmations: 312
    height: 1454616
    satoshis: 13146099
    scriptPubKey: "76a9142934df865df1baf8b2172cd750bc0179dbdea29288ac" // or locking script for mjGqLcJgCkJzHiXXNipBWVgvgVPWt49L2S
    txid: "3b67f694e6c5490d3b61c7c534e7e43078c270ae0e1d6f9a9b8b9440c5494fc1" // previous transaction hash 
    vout: 1
  }
}
```

![Previous transaction hash picture](https://raw.githubusercontent.com/cypherpunk99/bitcoinTx/master/prevTransactionHash.png)


# Sign via library `bitcoinjs-lib`

Stacktrace npm bitcoinjs-lib library `sign` method of class `TransactionBuilder`. And print results right into swap:
![Swap console](https://raw.githubusercontent.com/cypherpunk99/bitcoinTx/master/consoleSwap.png)


```javascript
  TransactionBuilder.prototype.sign = function (vin, keyPair, redeemScript, hashType, witnessValue, witnessScript) { // https://github.com/bitcoinjs/bitcoinjs-lib/blob/46c1991efacbe97b3d846fcd2763b5a23b3308d5/src/transaction_builder.js#L642
  // =>
  signatureHash = this.tx.hashForSignature(vin, input.signScript, hashType) // https://github.com/bitcoinjs/bitcoinjs-lib/blob/46c1991efacbe97b3d846fcd2763b5a23b3308d5/src/transaction_builder.js#L682
  // =>
  Transaction.prototype.hashForSignature = function (inIndex, prevOutScript, hashType) { // https://github.com/bitcoinjs/bitcoinjs-lib/blob/46c1991efacbe97b3d846fcd2763b5a23b3308d5/src/transaction.js#L254
  // => 
  console.log("!!HEX!! ", txTmp.toHex()); // !!HEX!!
  // => 
  return bcrypto.hash256(buffer) // https://github.com/bitcoinjs/bitcoinjs-lib/blob/46c1991efacbe97b3d846fcd2763b5a23b3308d5/src/transaction.js#L316
  // =>
  // Equals secp256k1(signatureHash, privateKey)
  const signature = keyPair.sign(signatureHash) // https://github.com/bitcoinjs/bitcoinjs-lib/blob/46c1991efacbe97b3d846fcd2763b5a23b3308d5/src/transaction_builder.js#L695
  // Returns (r, s)  
```
![before HEX](https://raw.githubusercontent.com/cypherpunk99/bitcoinTx/master/beforeHex.png)

![Returns (r, s)](https://raw.githubusercontent.com/cypherpunk99/bitcoinTx/master/rsSegp.png)



Snippet of code from `index.js`:

```javascript
  console.log('====---== keyPair.sign(signatureHash) ', signature);
  console.log('r ', signature.r.toString(16));
  console.log('s ', signature.s.toString(16));
```

Lets parse unsigned & signed transactions by hands. Helpfull link here
https://medium.com/coinmonks/bitcoin-p2pkh-transaction-breakdown-bb663034d6df

```javascript
  // Unsigned transaction
  // 0100000001c14f49c540948b9b9a6f1d0eae70c27830e4e734c5c7613b0d49c5e694f6673b010000001976a9142934df865df1baf8b2172cd750bc0179dbdea29288acfeffffff0228230000000000001976a91467643e0d5442d43275189ea648aeb02aeae38a1a88ace458c800000000001976a9142934df865df1baf8b2172cd750bc0179dbdea29288ac00000000
  // ------
  // 01000000 Version Number
  // 01 - number of outpoints (inputs)
  // c14f49c540948b9b9a6f1d0eae70c27830e4e734c5c7613b0d49c5e694f6673b - previous transaction hash in little endian format.
  // 01000000 - The last four bytes of the outpoint define the index of which UTXO of the previous transaction is being consumed.
  // 1976a9142934df865df1baf8b2172cd750bc0179dbdea29288ac - locking script for mjGqLcJgCkJzHiXXNipBWVgvgVPWt49L2S
  // feffffff - Sequence Number (nSequence)
  // 02 - number of outputs
  // Outputs:
  // 2823000000000000 - first output amount -  0x00002328 - 9000 satoshi
  // 1976a91467643e0d5442d43275189ea648aeb02aeae38a1a88ac - first locking script
  // e458c80000000000 - second output amount - 0x00c858e4 - 13129956 satoshi
  // 1976a9142934df865df1baf8b2172cd750bc0179dbdea29288ac - locking script or scriptPubKey for mjGqLcJgCkJzHiXXNipBWVgvgVPWt49L2S
  // 00000000

  /// Broadcast ready signed transaction   
  // 0100000001c14f49c540948b9b9a6f1d0eae70c27830e4e734c5c7613b0d49c5e694f6673b010000006a473044022035e3e8f906e882d6d4c5a36ebd112e3713a4ab1d9a3094eb347563a10ffc09b402201a036797437f40ae246c2e59d8bc7e552dd24c8d39c430877fef894e3df070870121034468b0a49321eebbd9032a8524c9bce1ab7f7abf192494641da294861926c449feffffff0228230000000000001976a91467643e0d5442d43275189ea648aeb02aeae38a1a88ace458c800000000001976a9142934df865df1baf8b2172cd750bc0179dbdea29288ac00000000
  // ------
  // 01000000 Version Number   
  // 01 - number of outpoints (inputs)
  // c14f49c540948b9b9a6f1d0eae70c27830e4e734c5c7613b0d49c5e694f6673b - 3b67f694e6c5490d3b61c7c534e7e43078c270ae0e1d6f9a9b8b9440c5494fc1 - previous transaction hash 
  // 01000000 - The last four bytes of the outpoint define the index of which UTXO of the previous transaction is being consumed.
  // 6a - Unlocking Script Length (0x6a) declares that the next 106 bytes are pushed to the stack 
  // Stack Script (Signature)
  // 47 - (0x47) declares that the next 71 bytes are the signature and sighash
  // 30 - DER signature marker
  // 44 - declares signature is 68 bytes in length
  // 02 - r value marker
  // 20 - declare r value is 32 bytes in length
  // r 35e3e8f906e882d6d4c5a36ebd112e3713a4ab1d9a3094eb347563a10ffc09b4  --------> NEW
  // 02 - s value marker
  // 20 - declare s value is 32 bytes in length
  // s 1a036797437f40ae246c2e59d8bc7e552dd24c8d39c430877fef894e3df07087  --------> NEW
  // 01 - sighash flag SIGHASH_ALL  = P2PKH
  // 21034468b0a49321eebbd9032a8524c9bce1ab7f7abf192494641da294861926c449 - Redeem Script --------> NEW
  // feffffff - Sequence Number (nSequence)
  // 02 - number of outputs
  // Outputs:
  // 2823000000000000 - first output amount -  0x00002328 - 9000 satoshi
  // 1976a91467643e0d5442d43275189ea648aeb02aeae38a1a88ac - first locking script
  // e458c80000000000 - second output amount - 0x00c858e4 - 13129956 satoshi
  // 1976a9142934df865df1baf8b2172cd750bc0179dbdea29288ac - locking script for mjGqLcJgCkJzHiXXNipBWVgvgVPWt49L2S
  // 00000000

```

# Sign via keychain

mykey:
```javascript
{
  "filetype": "TYPE_KEY",
  "keyname": "mykey",
  "description": "",
  "keychain_version": "0.13",
  "creation_time": "2019-01-25T17:11:06",
  "usage_time": "1970-01-01T00:00:00",
  "keyinfo": {
    "encrypted": false,
    "curve_type": "secp256k1",
    "priv_key_data": "5fda7b741910b05738c5e0ca8961cf7a9c2f3afe8dfcae8d57df5f01690f2a02",
    "public_key": "034468b0a49321eebbd9032a8524c9bce1ab7f7abf192494641da294861926c449"
  }
}
```

```javascript
  const alice = bitcoin.ECPair.fromWIF('cQo2bAcaAXA9HiZaTQmSgn5Vk4xjnC2xRzSnNcXHT4JnetMCsiJ6', bitcoin.networks.testnet)
  console.log('publicKey ', alice.publicKey.toString('hex'));
  console.log('privateKey ', alice.privateKey.toString('hex'));
```



![node index.js command](https://raw.githubusercontent.com/cypherpunk99/bitcoinTx/master/nodeIndex.png)


Result:

```
publicKey  034468b0a49321eebbd9032a8524c9bce1ab7f7abf192494641da294861926c449
privateKey  5fda7b741910b05738c5e0ca8961cf7a9c2f3afe8dfcae8d57df5f01690f2a02
```

Singing via keychain:

```javascript
{
  "command": "sign_hex",
  "params": {
    "transaction": "0100000001c14f49c540948b9b9a6f1d0eae70c27830e4e734c5c7613b0d49c5e694f6673b010000001976a9142934df865df1baf8b2172cd750bc0179dbdea29288acfeffffff0228230000000000001976a91467643e0d5442d43275189ea648aeb02aeae38a1a88ace458c800000000001976a9142934df865df1baf8b2172cd750bc0179dbdea29288ac00000000",
    "blockchain_type": "bitcoin",
    "keyname": "mykey"
  }
}
```

![sign_hex Keychain](https://raw.githubusercontent.com/cypherpunk99/bitcoinTx/master/signHexKeychain.png)



Result: `e8f366d9707c2b34fd0c889a303a7d148768426ba05534a76098380a34ca22732a312c18835dd3999b03800de9124192b2ce062ef93bcf83f15bbd254b04ecbb00`

Compare with:
r: `35e3e8f906e882d6d4c5a36ebd112e3713a4ab1d9a3094eb347563a10ffc09b4`
s: `1a036797437f40ae246c2e59d8bc7e552dd24c8d39c430877fef894e3df07087`


# Resume

`[Unsigned Transaction] => sha256([Unsigned Transaction]) => secp256k1([sha256([Unsigned Transaction])]) => (r, s) => concat([Unsigned Transaction], (r, s)) === [Signed transaction]`

Fix it:

```cpp
  case blockchain_te::bitcoin:
    {
      unit_list.push_back(raw);
      auto hash = get_hash(unit_list, sha2_256_encoder());
      unit_list.clear();
      unit_list.push_back(hash.asBytes());
      auto hash2 = get_hash(unit_list, sha2_256_encoder());
      signature = dev::sign(private_key,dev::FixedHash<32>(((byte const*) hash2.data()),
                                  dev::FixedHash<32>::ConstructFromPointerType::ConstructFromPointer));
      break;
    }

```

Other links:
 - https://ru.bitcoinwiki.org/wiki/P2PKH
 - https://bitcoin.org/en/developer-guide#transactions
