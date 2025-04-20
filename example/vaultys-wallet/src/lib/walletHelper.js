// Import ECPair with dynamic import for browser compatibility
import * as bitcoin from "bitcoinjs-lib";
import { computeLocalPRF, requestPRFComputation, getDerivationPath } from "./identityHelper";
import ECPairFactory from "ecpair";
import * as ecc from "tiny-secp256k1";
import BIP32Factory from "bip32";
import { crypto } from "@vaultys/id";

// Initialize crypto libraries with normal imports
const ECPair = ECPairFactory(ecc);
const bip32 = BIP32Factory(ecc);

// Network settings (testnet for development)
const network = bitcoin.networks.testnet;

// Initialize wallet
export async function initializeWallet(idManager, useRemotePRF = true, callbacks = {}) {
  try {
    // Use remote PRF if specified, otherwise fall back to local
    const derivationPath = getDerivationPath();
    let seed;

    if (useRemotePRF) {
      try {
        // Set up status updates if callbacks are provided
        const { onChannelSetup, onStatusUpdate } = callbacks;

        const { result, channelUrl } = await requestPRFComputation(idManager, derivationPath, {
          onChannelSetup: (info) => {
            // Update QR code
            if (onChannelSetup) onChannelSetup(info);
          },
          onStatusUpdate: (status) => {
            // Update status message
            if (onStatusUpdate) onStatusUpdate(status);
          },
        });

        seed = result;
        localStorage.setItem("lastChannelUrl", channelUrl);
      } catch (error) {
        console.warn("Remote PRF failed, falling back to local:", error);
        seed = await computeLocalPRF(idManager, derivationPath);
      }
    } else {
      seed = await computeLocalPRF(idManager, derivationPath);
    }

    // Convert PRF result to seed
    const seedHex = Buffer.from(crypto.hash("512", seed)).toString("hex");

    // Generate master node
    const root = bip32.fromSeed(Buffer.from(seedHex, "hex"), network);

    // Store wallet info in localStorage
    const walletInfo = {
      initialized: true,
      accountIndex: 0,
      lastAddressIndex: 0,
      addresses: [],
    };

    localStorage.setItem("walletInfo", JSON.stringify(walletInfo));

    return { root, walletInfo };
  } catch (error) {
    console.error("Error initializing wallet:", error);
    throw new Error("Failed to initialize wallet: " + error.message);
  }
}

// Generate new address
export async function generateAddress(idManager, addressIndex, useRemotePRF = true) {
  try {
    const walletInfo = JSON.parse(localStorage.getItem("walletInfo") || "{}");

    if (!walletInfo.initialized) {
      throw new Error("Wallet not initialized");
    }

    // Derive path for this specific address
    const derivationPath = getDerivationPath(addressIndex);

    let seed;
    if (useRemotePRF) {
      try {
        const { result } = await requestPRFComputation(idManager, derivationPath);
        seed = result;
      } catch (error) {
        console.warn("Remote PRF failed, falling back to local:", error);
        seed = await computeLocalPRF(idManager, derivationPath);
      }
    } else {
      seed = await computeLocalPRF(idManager, derivationPath);
    }

    // Convert PRF result to private key
    const seedHex = Buffer.from(crypto.hash("512", seed)).toString("hex");
    const root = bip32.fromSeed(Buffer.from(seedHex, "hex"), network);

    // Generate address using p2wpkh (Native SegWit)
    const { address } = bitcoin.payments.p2wpkh({
      pubkey: root.publicKey,
      network,
    });

    // Update wallet info
    walletInfo.lastAddressIndex = Math.max(walletInfo.lastAddressIndex, addressIndex);

    // Add to address list if not already there
    if (!walletInfo.addresses.some((a) => a.address === address)) {
      walletInfo.addresses.push({
        index: addressIndex,
        address,
        path: derivationPath,
        created: new Date().toISOString(),
      });
    }

    localStorage.setItem("walletInfo", JSON.stringify(walletInfo));

    return { address, index: addressIndex };
  } catch (error) {
    console.error("Error generating address:", error);
    throw new Error("Failed to generate address: " + error.message);
  }
}

// Get wallet balance from API
export async function getBalance(address) {
  try {
    // Use a Bitcoin testnet API for development
    const response = await fetch(`https://blockstream.info/testnet/api/address/${address}`);

    if (!response.ok) {
      throw new Error(`API error: ${response.status}`);
    }

    const data = await response.json();

    // Convert from satoshis to BTC
    const balanceBTC = (data.chain_stats.funded_txo_sum - data.chain_stats.spent_txo_sum) / 100000000;
    const unconfirmedBTC = (data.mempool_stats.funded_txo_sum - data.mempool_stats.spent_txo_sum) / 100000000;

    return {
      confirmed: balanceBTC,
      unconfirmed: unconfirmedBTC,
      total: balanceBTC + unconfirmedBTC,
    };
  } catch (error) {
    console.error("Error fetching balance:", error);
    return { confirmed: 0, unconfirmed: 0, total: 0 };
  }
}

// Get UTXOs (unspent transaction outputs) for the address
export async function getUTXOs(address) {
  try {
    const response = await fetch(`https://blockstream.info/testnet/api/address/${address}/utxo`);

    if (!response.ok) {
      throw new Error(`API error: ${response.status}`);
    }

    return await response.json();
  } catch (error) {
    console.error("Error fetching UTXOs:", error);
    return [];
  }
}

// Fetch detailed UTXO information
async function fetchTxDetail(txid) {
  try {
    const response = await fetch(`https://blockstream.info/testnet/api/tx/${txid}/hex`);

    if (!response.ok) {
      throw new Error(`API error: ${response.status}`);
    }

    const txHex = await response.text();
    return bitcoin.Transaction.fromHex(txHex);
  } catch (error) {
    console.error("Error fetching transaction details:", error);
    throw error;
  }
}

// Sign a transaction
export async function signTransaction(idManager, txData, addressIndex, useRemotePRF = true) {
  try {
    // Derive keys for signing
    const derivationPath = getDerivationPath(addressIndex);

    let seed;
    if (useRemotePRF) {
      try {
        const { result } = await requestPRFComputation(idManager, derivationPath);
        seed = result;
      } catch (error) {
        console.warn("Remote PRF failed, falling back to local:", error);
        seed = await computeLocalPRF(idManager, derivationPath);
      }
    } else {
      seed = await computeLocalPRF(idManager, derivationPath);
    }

    // Convert PRF result to private key
    const seedHex = Buffer.from(crypto.hash("512", seed)).toString("hex");
    const root = bip32.fromSeed(Buffer.from(seedHex, "hex"), network);

    // Create a keyPair from the private key
    const keyPair = ECPair.fromPrivateKey(root.privateKey, { network });

    // Create a transaction builder
    const psbt = new bitcoin.Psbt({ network });

    // Fetch real UTXOs
    const utxos = await getUTXOs(txData.sourceAddress);

    if (utxos.length === 0) {
      throw new Error("No unspent outputs found for this address");
    }

    // Calculate total input amount
    let totalInput = 0;

    // Add inputs
    for (const utxo of utxos) {
      const txDetail = await fetchTxDetail(utxo.txid);

      psbt.addInput({
        hash: utxo.txid,
        index: utxo.vout,
        witnessUtxo: {
          script: bitcoin.address.toOutputScript(txData.sourceAddress, network),
          value: utxo.value,
        },
        // Add the public key needed for signing
        tapInternalKey: root.publicKey,
      });

      totalInput += utxo.value;

      // If we have enough inputs to cover the transaction, stop adding more
      if (totalInput >= txData.amount + txData.fee) {
        break;
      }
    }

    if (totalInput < txData.amount + txData.fee) {
      throw new Error(`Insufficient funds. Required: ${(txData.amount + txData.fee) / 100000000} BTC, Available: ${totalInput / 100000000} BTC`);
    }

    // Add the output (destination address and amount)
    psbt.addOutput({
      address: txData.destinationAddress,
      value: txData.amount,
    });

    // Add change output if needed
    const changeAmount = totalInput - txData.amount - txData.fee;
    if (changeAmount > 546) {
      // Dust threshold
      psbt.addOutput({
        address: txData.sourceAddress, // Send change back to source
        value: changeAmount,
      });
    }

    // Sign all inputs
    for (let i = 0; i < psbt.data.inputs.length; i++) {
      psbt.signInput(i, keyPair);
    }

    // Finalize and extract transaction
    psbt.finalizeAllInputs();
    const tx = psbt.extractTransaction();

    return {
      txHex: tx.toHex(),
      txId: tx.getId(),
    };
  } catch (error) {
    console.error("Error signing transaction:", error);
    throw new Error("Failed to sign transaction: " + error.message);
  }
}

// Estimate transaction fee
export async function estimateFee(satoshisPerByte = 10) {
  try {
    // You could fetch this from a fee estimation API
    // For simplicity, we'll use a fixed formula based on typical transaction size
    const estimatedTxSize = 250; // bytes (typical P2WPKH transaction)
    return satoshisPerByte * estimatedTxSize;
  } catch (error) {
    console.error("Error estimating fee:", error);
    // Return a reasonable default fee
    return 2500; // 10 sat/byte * 250 bytes
  }
}

// Broadcast a signed transaction
export async function broadcastTransaction(txHex) {
  try {
    // Use a Bitcoin testnet API for development
    const response = await fetch("https://blockstream.info/testnet/api/tx", {
      method: "POST",
      body: txHex,
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Failed to broadcast: ${error}`);
    }

    const txId = await response.text();
    return { success: true, txId };
  } catch (error) {
    console.error("Error broadcasting transaction:", error);
    throw new Error("Failed to broadcast transaction: " + error.message);
  }
}

// Get transaction history
export async function getTransactionHistory(address) {
  try {
    // Use a Bitcoin testnet API for development
    const response = await fetch(`https://blockstream.info/testnet/api/address/${address}/txs`);

    if (!response.ok) {
      throw new Error(`API error: ${response.status}`);
    }

    const transactions = await response.json();

    return transactions.map((tx) => ({
      txid: tx.txid,
      confirmed: tx.status.confirmed,
      block_height: tx.status.block_height || 0,
      time: tx.status.block_time ? new Date(tx.status.block_time * 1000).toISOString() : null,
      value: calculateTransactionValue(tx, address),
      type: determineTransactionType(tx, address),
    }));
  } catch (error) {
    console.error("Error fetching transaction history:", error);
    return [];
  }
}

// Calculate the value of a transaction from perspective of the address
function calculateTransactionValue(tx, address) {
  let received = 0;
  let sent = 0;

  // Sum outputs to the address (received)
  tx.vout.forEach((output) => {
    if (output.scriptpubkey_address === address) {
      received += output.value;
    }
  });

  // Sum inputs from the address (sent)
  tx.vin.forEach((input) => {
    if (input.prevout && input.prevout.scriptpubkey_address === address) {
      sent += input.prevout.value;
    }
  });

  // Return net value (received - sent)
  return (received - sent) / 100000000; // Convert satoshis to BTC
}

// Determine if transaction is incoming or outgoing
function determineTransactionType(tx, address) {
  let received = 0;
  let sent = 0;

  // Sum outputs to the address (received)
  tx.vout.forEach((output) => {
    if (output.scriptpubkey_address === address) {
      received += output.value;
    }
  });

  // Sum inputs from the address (sent)
  tx.vin.forEach((input) => {
    if (input.prevout && input.prevout.scriptpubkey_address === address) {
      sent += input.prevout.value;
    }
  });

  if (sent > 0 && received > 0) {
    return "self"; // Sending to self or change
  } else if (sent > 0) {
    return "outgoing";
  } else {
    return "incoming";
  }
}

// Validate Bitcoin address
export function isValidAddress(address) {
  try {
    bitcoin.address.toOutputScript(address, network);
    return true;
  } catch (error) {
    return false;
  }
}

// Format BTC amount
export function formatBTC(amount) {
  return parseFloat(amount).toFixed(8);
}

// Convert satoshis to BTC
export function satoshisToBTC(satoshis) {
  return satoshis / 100000000;
}

// Convert BTC to satoshis
export function btcToSatoshis(btc) {
  return Math.floor(btc * 100000000);
}
