/// SPDX-License-Identifier: MIT
pragma solidity ^0.8.14;

import "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC1155/extensions/ERC1155Burnable.sol";

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract Metagame is ERC1155, Ownable, ERC1155Burnable {
    using SafeERC20 for IERC20;

    uint256 public _nextTokenId;
    bytes32 public immutable DOMAIN_SEPARATOR;
    mapping(address => bool) private _validSigners;
    mapping(uint256 => uint256) public tokenPrices;
    mapping(uint256 => string) public tokenURIs;

    // keccak256("Mint(address minter,uint256 tokenId)");
    bytes32 public constant MINT_TYPEHASH =
        0xa606813b74b4f7a622ceaeb55dea14601d0e31c3ba68af131365453b2e0686c7;

    /// @dev We don't use the _uri field on the contract, and instead store a URI per tokenId
    constructor() ERC1155("") {
        _nextTokenId = 1;
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256(bytes("Metagame")),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

    function setValidSigner(address signer, bool valid) public onlyOwner {
        _validSigners[signer] = valid;
    }

    function setTokenPrice(uint256 tokenId, uint256 price) public onlyOwner {
        tokenPrices[tokenId] = price;
    }

    function setTokenURI(uint256 tokenId, string calldata _uri)
        public
        onlyOwner
    {
        tokenURIs[tokenId] = _uri;
    }

    function create(string calldata _uri, uint256 tokenPrice)
        external
        onlyOwner
    {
        uint256 tokenId = _nextTokenId;
        tokenPrices[tokenId] = tokenPrice;
        tokenURIs[tokenId] = _uri;
        _nextTokenId++;
    }

    function mintWithSignature(
        uint8 v,
        bytes32 r,
        bytes32 s,
        address minter,
        uint256 tokenId
    ) external payable {
        require(minter == msg.sender, "Cannot mint for different account");
        require(msg.value == tokenPrices[tokenId], "Incorrect amount paid");
        // URI for token not being set is a proxy for non-initialization.
        // Only the contract owner can create a new token.
        require(bytes(tokenURIs[tokenId]).length != 0, "Token doesn't exist");
        // We can avoid using nonces, checking that the user hasn't minted that
        // tokenID inherently invalidates replay attacks
        require(balanceOf(minter, tokenId) == 0, "Token already minted");

        bytes32 mintHash = keccak256(
            abi.encode(
                keccak256("Mint(address minter,uint256 tokenId)"),
                minter,
                tokenId
            )
        );

        bytes32 hash = keccak256(
            abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, mintHash)
        );
        address signer = ecrecover(hash, v, r, s);
        require(signer != address(0), "ECDSA: invalid signature");
        require(isValidSigner(signer), "Invalid signer");

        _mint(minter, tokenId, 1, "");
    }

    function uri(uint256 tokenId) public view override returns (string memory) {
        return tokenURIs[tokenId];
    }

    function isValidSigner(address signer) internal view returns (bool) {
        return _validSigners[signer];
    }

    function withdraw() public payable onlyOwner {
        (bool success, ) = payable(msg.sender).call{
            value: address(this).balance
        }("");
        require(success);
    }

    function recoverERC20(
        address recipient,
        address token,
        uint256 amount
    ) external onlyOwner {
        IERC20(token).safeTransfer(recipient, amount);
    }

    function _beforeTokenTransfer(
        address operator,
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    ) internal override(ERC1155) {
        // Token can be minted and burned but not transferred.
        require(
            from == address(0x0) || to == address(0x0),
            "Transfers disabled"
        );
        super._beforeTokenTransfer(operator, from, to, ids, amounts, data);
    }

    /// This function is called for all messages sent to this contract.
    /// Sending Ether to this contract will cause an exception because
    /// the fallback function does not have the `payable` modifier.
    /// Source: https:///docs.soliditylang.org/en/v0.8.4/contracts.html?highlight=fallback#fallback-function
    fallback() external {}
}
