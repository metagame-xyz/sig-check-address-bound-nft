// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.14;

import "forge-std/Test.sol";
import "../src/Metagame.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract Token is ERC20 {
    constructor(address _game) ERC20("Fake", "FAKE") {
        _mint(_game, 1 ether);
    }
}

contract MetagameTest is Test {
    Metagame game;
    address owner = address(1);
    uint256 minterPrivateKey = 0xBAD;
    address minter = vm.addr(minterPrivateKey);
    uint256 signerPrivateKey = 0xDAD;
    address signer = vm.addr(signerPrivateKey);
    address invalidMinter = address(2);
    ERC20 token;

    function generateDigest(bytes32 mintHash) internal view returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    "\x19\x01",
                    keccak256(
                        abi.encode(
                            keccak256(
                                "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                            ),
                            keccak256(bytes("Metagame")),
                            keccak256(bytes("1")),
                            block.chainid,
                            address(game)
                        )
                    ),
                    mintHash
                )
            );
    }

    function validSignature(uint256 tokenId) private returns (uint8 v, bytes32 r, bytes32 s) {
        bytes32 mintHash = keccak256(
            abi.encode(
                keccak256("Mint(address minter,uint256 tokenId)"),
                minter,
                tokenId
            )
        );
        bytes32 digest = generateDigest(mintHash);
        return vm.sign(signerPrivateKey, digest);        
    }

    function setUp() public {
        vm.startPrank(owner);
        game = new Metagame();
        game.create("ipfs://1234", .1 ether);
        game.setValidSigner(signer, true);
        token = new Token(address(game));
        vm.stopPrank();
    }

    function testMintWithValidSignature() public {
        vm.deal(minter, .2 ether);
        vm.startPrank(minter);
        (uint8 v, bytes32 r, bytes32 s) = validSignature(1);
        game.mintWithSignature{value: .1 ether}(v, r, s, minter, 1);
        assert(game.balanceOf(minter, 1) == 1);
        assert(minter.balance == .1 ether);
        assertEq(game.uri(1), string(abi.encodePacked("ipfs://1234")));
    }

    function testValidSignatureReplayFails() public {
        vm.deal(minter, .2 ether);
        vm.startPrank(minter);
        (uint8 v, bytes32 r, bytes32 s) = validSignature(1);
        game.mintWithSignature{value: .1 ether}(v, r, s, minter, 1);
        vm.expectRevert(bytes("Token already minted"));
        game.mintWithSignature{value: .1 ether}(v, r, s, minter, 1);
    }

    function testValidSignatureDifferentCallerFails() public {
        vm.deal(minter, .2 ether);
        vm.startPrank(minter);
        (uint8 v, bytes32 r, bytes32 s) = validSignature(1);
        game.mintWithSignature{value: .1 ether}(v, r, s, minter, 1);
        vm.expectRevert(bytes("Cannot mint for different account"));
        game.mintWithSignature{value: .1 ether}(v, r, s, invalidMinter, 1);
    }

    function testSignatureMinterMismatchFails() public {
        vm.deal(minter, .2 ether);
        vm.startPrank(minter);
        bytes32 mintHash = keccak256(
            abi.encode(
                keccak256("Mint(address minter,uint256 tokenId)"),
                invalidMinter,
                1
            )
        );
        bytes32 digest = generateDigest(mintHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, digest);
        vm.expectRevert(bytes("Invalid signer"));
        game.mintWithSignature{value: .1 ether}(v, r, s, minter, 1);
    }

    function testValidSignatureWithInvalidSignerFails() public {
        vm.deal(minter, .2 ether);
        vm.startPrank(minter);
        bytes32 mintHash = keccak256(
            abi.encode(
                keccak256("Mint(address minter,uint256 tokenId)"),
                minter,
                1
            )
        );
        bytes32 digest = generateDigest(mintHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(minterPrivateKey, digest);
        vm.expectRevert(bytes("Invalid signer"));
        game.mintWithSignature{value: .1 ether}(v, r, s, minter, 1);
    }

    function testInvalidSignatureFails() public {
        vm.deal(minter, .2 ether);
        vm.startPrank(minter);
        bytes32 mintHash = keccak256(
            abi.encode(
                keccak256("Mint(address minter,uint256 tokenId)"),
                minter,
                1
            )
        );
        bytes32 digest = generateDigest(mintHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(minterPrivateKey, digest);
        vm.expectRevert(bytes("ECDSA: invalid signature"));
        game.mintWithSignature{value: .1 ether}(v - 10, r, s, minter, 1);
    }

    function testCreateNewToken() public {
        vm.prank(owner);
        game.create("ipfs://12345", .3 ether);
        assertEq(game.uri(2), string(abi.encodePacked("ipfs://12345")));

        vm.startPrank(minter);
        (uint8 v, bytes32 r, bytes32 s) = validSignature(2);
        vm.expectRevert("Incorrect amount paid");
        game.mintWithSignature{value: 0 ether}(v, r, s, minter, 2);

        vm.deal(minter, .3 ether);
        game.mintWithSignature{value: .3 ether}(v, r, s, minter, 2);
        assert(game.balanceOf(minter, 2) == 1);
    }

    function testSignatureWrongTokenIdFails() public {
        vm.prank(owner);
        game.create("ipfs://12345", .3 ether);
        assertEq(game.uri(2), string(abi.encodePacked("ipfs://12345")));


        vm.deal(minter, .3 ether);
        vm.startPrank(minter);
        (uint8 v, bytes32 r, bytes32 s) = validSignature(1);
        vm.expectRevert(bytes("Invalid signer"));
        game.mintWithSignature{value: .3 ether}(v, r, s, minter, 2);
    }

    function testSignatureNoTokenIDFails() public {
        vm.deal(minter, .3 ether);
        vm.prank(minter);
        (uint8 v, bytes32 r, bytes32 s) = validSignature(2);
        vm.expectRevert("Incorrect amount paid");
        game.mintWithSignature{value: .3 ether}(v, r, s, minter, 2);

        vm.prank(owner);
        game.setTokenPrice(2, .3 ether);
        vm.prank(minter);
        vm.expectRevert("Token doesn't exist");
        game.mintWithSignature{value: .3 ether}(v, r, s, minter, 2);
    }

    function testBurn() public {
        vm.deal(minter, .2 ether);
        vm.startPrank(minter);
        (uint8 v, bytes32 r, bytes32 s) = validSignature(1);
        game.mintWithSignature{value: .1 ether}(v, r, s, minter, 1);
        assert(game.balanceOf(minter, 1) == 1);
        game.burn(minter, 1, 1);
        assert(game.balanceOf(minter, 1) == 0);
    }

    function testTransferFails() public {
        vm.deal(minter, .2 ether);
        vm.startPrank(minter);
        (uint8 v, bytes32 r, bytes32 s) = validSignature(1);
        game.mintWithSignature{value: .1 ether}(v, r, s, minter, 1);
        assert(game.balanceOf(minter, 1) == 1);
        vm.expectRevert("Transfers disabled");
        game.safeTransferFrom(minter, invalidMinter, 1, 1, "");
        assert(game.balanceOf(minter, 1) == 1);
    }


    function testWithdrawEth() public {
        vm.startPrank(owner);
        assert(address(game).balance == 0);
        vm.deal(address(game), 1 ether);
        game.withdraw();
        assert(owner.balance == 1 ether);
    }

    function testRecoverERC20() public {
         vm.startPrank(owner);
        assert(token.balanceOf(owner) == 0);
        game.recoverERC20(owner, address(token), 1 ether);
        assert(token.balanceOf(owner) == 1 ether);
    }
}
