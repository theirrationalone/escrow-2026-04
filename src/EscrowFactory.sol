// SPDX-License-Identifier: MIT

// @info: This's the auditor (theirrationalone) who's modified the pragma solidity version to ^0.8.20, the original version is 0.8.18 and that's all okay, so no issues here.
pragma solidity ^0.8.20;

import {IEscrowFactory} from "./IEscrowFactory.sol";
import {IEscrow} from "./IEscrow.sol";
import {Escrow} from "./Escrow.sol";

// @info: all below imports are from openzeppelin, so no issues here too.
// @TODOs: Head to learn everything about these imports. what they're? why they are used?, and how imparative they are actually in context of this protocol solution's security and functionality.
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/// @author Cyfrin
/// @title EscrowFactory
/// @notice Factory contract for deploying Escrow contracts.
contract EscrowFactory is IEscrowFactory {
    using SafeERC20 for IERC20;

    /// @inheritdoc IEscrowFactory
    /// @dev msg.sender must approve the token contract to spend the price amount before calling this function.
    /// @dev There is a risk that if a malicious token is used, the dispute process could be manipulated.
    /// Therefore, careful consideration should be taken when chosing the token.
    function newEscrow(
        uint256 price,
        IERC20 tokenContract,
        address seller,
        address arbiter,
        uint256 arbiterFee,
        bytes32 salt
    ) external returns (IEscrow) {
        address computedAddress = computeEscrowAddress(
            type(Escrow).creationCode,
            address(this),
            uint256(salt),
            price,
            tokenContract,
            msg.sender,
            seller,
            arbiter,
            arbiterFee
        );
        // @BUG: Funds lost possibility
        // @reason: perceived or computed escrow address may result to a mismatch with the actual escrow address
        tokenContract.safeTransferFrom(msg.sender, computedAddress, price);
        
        // @info: salt could the victim, possible front-running MEV
        // @note: already a known-issue
        // @info: It's buyer's (deployer|msg.sender) best interest to deploy the escrow best.
        Escrow escrow = new Escrow{salt: salt}(
            price,
            tokenContract,
            msg.sender, 
            seller,
            arbiter,
            arbiterFee
        );
        if (address(escrow) != computedAddress) {
            revert EscrowFactory__AddressesDiffer();
        }
        emit EscrowCreated(address(escrow), msg.sender, seller, arbiter);

        // @question: can two or more identical contracts be created using same & redundant inputs???
        // @assumption: if yes, then, sniffed doubtfull BUGs in escrow would all become real and there could have even more disruptive outcomes too.
        return escrow;
    }

    /// @dev See https://docs.soliditylang.org/en/latest/control-structures.html#salted-contract-creations-create2
    function computeEscrowAddress(
        bytes memory byteCode,
        address deployer,
        uint256 salt,
        uint256 price,
        IERC20 tokenContract,
        address buyer,
        address seller,
        address arbiter,
        uint256 arbiterFee
    ) public pure returns (address) {
        // @TODO: verify the raw contract address computation method and all injected inputs.
        address predictedAddress = address(
            uint160(
                uint256(
                    keccak256(
                        abi.encodePacked(
                            bytes1(0xff),
                            deployer,
                            salt,
                            keccak256(
                                abi.encodePacked(
                                    byteCode, abi.encode(price, tokenContract, buyer, seller, arbiter, arbiterFee)
                                )
                            )
                        )
                    )
                )
            )
        );
        return predictedAddress;
    }
}
