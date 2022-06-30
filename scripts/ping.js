const ethers = require('ethers');

const provider = ethers.getDefaultProvider();
const abi = ["function tokenURI(uint256) external view returns (string)"];
const address = "0x4ef107a154cb7580c686c239ed9f92597a42b961";

const contract = new ethers.Contract(address, abi, provider);
contract.tokenURI(161).then(console.log)