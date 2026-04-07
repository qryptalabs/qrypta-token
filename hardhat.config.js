require("@nomicfoundation/hardhat-toolbox");
require("dotenv").config();

const {
  PRIVATE_KEY,
  BSC_MAINNET_RPC_URL,
  BSC_TESTNET_RPC_URL,
  ETH_MAINNET_RPC_URL,
  BSCSCAN_API_KEY,
  ETHERSCAN_API_KEY
} = process.env;

function getAccounts() {
  return PRIVATE_KEY ? [PRIVATE_KEY] : [];
}

module.exports = {
  solidity: {
    version: "0.8.24",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200
      },
      evmVersion: "paris"
    }
  },
  networks: {
    bsc: {
      url: BSC_MAINNET_RPC_URL || "",
      chainId: 56,
      accounts: getAccounts()
    },
    bscTestnet: {
      url: BSC_TESTNET_RPC_URL || "",
      chainId: 97,
      accounts: getAccounts()
    },
    ethereum: {
      url: ETH_MAINNET_RPC_URL || "",
      chainId: 1,
      accounts: getAccounts()
    }
  },
  etherscan: {
    apiKey: {
      bsc: BSCSCAN_API_KEY || "",
      bscTestnet: BSCSCAN_API_KEY || "",
      mainnet: ETHERSCAN_API_KEY || ""
    }
  }
};
