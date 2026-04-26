// SPDX-License-Identifier: MIT

// @info: This's the auditor (theirrationalone) who's modified the pragma solidity version to ^0.8.20, the original version is 0.8.18 and that's all okay, so no issues here.
pragma solidity ^0.8.20;

// Inspired by `BillOfSaleERC20` contract: https://github.com/open-esq/Digital-Organization-Designs/blob/master/Finance/BillofSaleERC20.sol

// @follow-up: analysis remains for IEscrow.
import {IEscrow} from "./IEscrow.sol";

// @info: all below imports are from openzeppelin, so no issues here too.
// @TODOs: Head to learn everything about these imports. what they're? why they are used?, and how imparative they are actually in context of this protocol solution's security and functionality.
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

// @shout-out: Hayo Cyfrin ;`)
/// @author Cyfrin
/// @title Escrow
/// @notice Escrow contract for transactions between a seller, buyer, and optional arbiter.
// @info: Yeah, all linear inheritance, therefore no issues here.
contract Escrow is IEscrow, ReentrancyGuard {
    // @info: using safe version of erc20, tokens might flow in a more restricted way as compared of normal or vanilla erc20.
    // @caveat: Heavy restrictions on tokens could lead to over-protection issues sometimes.
    // @follow-up: requires to check its diligence diligently.
    using SafeERC20 for IERC20;

    uint256 private immutable i_price;
    /// @dev There is a risk that if a malicious token is used, the dispute process could be manipulated.
    /// Therefore, careful consideration should be taken when chosing the token.
    IERC20 private immutable i_tokenContract;
    address private immutable i_buyer;
    address private immutable i_seller;
    address private immutable i_arbiter;
    uint256 private immutable i_arbiterFee;

    State private s_state;

    /// @dev Sets the Escrow transaction values for `price`, `tokenContract`, `buyer`, `seller`, `arbiter`, `arbiterFee`. All of
    /// these values are immutable: they can only be set once during construction and reflect essential deal terms.
    /// @dev Funds should be sent to this address prior to its deployment, via create2. The constructor checks that the tokens have
    /// been sent to this address.
    constructor(
        uint256 price,
        IERC20 tokenContract,
        address buyer,
        address seller,
        address arbiter,
        uint256 arbiterFee
    ) {
        if (address(tokenContract) == address(0)) revert Escrow__TokenZeroAddress();
        if (buyer == address(0)) revert Escrow__BuyerZeroAddress();
        if (seller == address(0)) revert Escrow__SellerZeroAddress();
        // @info: not-so efficient check to prevent heavy arbiter fee.
        // this check can be bypassed with the arbiterFee just a penny less than the price.
        // @follow-up: does this contract has any function to update the arbiter fee? if not, then a better threshold or ratio based check is a must necessity.
        if (arbiterFee >= price) revert Escrow__FeeExceedsPrice(price, arbiterFee);
        // @question: is it okay to have token with excess balance?
        // @info: okay, so the price precision is token decimals based.
        if (tokenContract.balanceOf(address(this)) < price) revert Escrow__MustDeployWithTokenBalance();
        i_price = price;
        i_tokenContract = tokenContract;
        i_buyer = buyer;
        i_seller = seller;
        i_arbiter = arbiter;
        i_arbiterFee = arbiterFee;
        // @info: missing s_state initialization
        // @info: might default to created
    }

    /////////////////////
    // Modifiers
    /////////////////////

    /// @dev Throws if called by any account other than buyer.
    modifier onlyBuyer() {
        if (msg.sender != i_buyer) {
            revert Escrow__OnlyBuyer();
        }
        _;
    }

    /// @dev Throws if called by any account other than buyer or seller.
    modifier onlyBuyerOrSeller() {
        if (msg.sender != i_buyer && msg.sender != i_seller) {
            revert Escrow__OnlyBuyerOrSeller();
        }
        _;
    }

    /// @dev Throws if called by any account other than arbiter.
    modifier onlyArbiter() {
        // @info: known-issue empowerer, providing top notch of security over malicious actors though.
        if (msg.sender != i_arbiter) {
            revert Escrow__OnlyArbiter();
        }
        _;
    }

    /// @dev Throws if contract called in State other than one associated for function.
    modifier inState(State expectedState) {
        // @Gas: reading s_state twice directly from storage, which is a bit gas inefficient.
        if (s_state != expectedState) {
            revert Escrow__InWrongState(s_state, expectedState);
        }
        _;
    }

    /////////////////////
    // Functions
    /////////////////////

    /// @inheritdoc IEscrow
    // @info: should/must be possible after off-chain report hand-over to the buyer(a person or a contract receiving confirmation msg) from their linked seller
    // @ambiguous-known-issue-assumption: buyer never calls confirmReceipt - The terms of the Escrow are agreed upon by the buyer and seller before deploying it. The onus is on the seller to perform due diligence on the buyer and their off-chain identity/reputation before deciding to supply the buyer with their services.
    // @question: Why the heck it's a job of a seller to verify the credibility of the buyer?? then, why they hired an arbiter???
    // That should be the job of an arbiter, in our case for example, the codehawks & team might have some sort of reputed clients(buyers list) or accountability to confirm their buyers goodwill in the market and the quality of them.
    function confirmReceipt() external onlyBuyer inState(State.Created) {
        s_state = State.Confirmed;
        emit Confirmed(i_seller);

        // @BUG-1: Funds loss: a malicious seller could appear all legit and will sweep out all the tokens of this contract upon his audit receipt confirmation.
        // @verified: false
        // @BUG-2: DoS: chained to @BUG-1, consequences leads to a DoS for all other buyers(protocols) & sellers(auditors)
        // @verified: false
        // @BUG-3: chained Funds-loss -> DoS: CONSEQUENCED to ref @BUG-1 then @BUG-2 == @BUG-3
        // @verified: false
        // @question: does safeTranfer contains any delegate call??????? - reentrancy could be a suspicious torment in that case.
        i_tokenContract.safeTransfer(i_seller, i_tokenContract.balanceOf(address(this)));
    }

    /// @inheritdoc IEscrow
    function initiateDispute() external onlyBuyerOrSeller inState(State.Created) {
        if (i_arbiter == address(0)) revert Escrow__DisputeRequiresArbiter();
        s_state = State.Disputed;
        emit Disputed(msg.sender);
    }

    /// @inheritdoc IEscrow
    function resolveDispute(uint256 buyerAward) external onlyArbiter nonReentrant inState(State.Disputed) {
        uint256 tokenBalance = i_tokenContract.balanceOf(address(this));
        uint256 totalFee = buyerAward + i_arbiterFee; // Reverts on overflow
        if (totalFee > tokenBalance) {
            revert Escrow__TotalFeeExceedsBalance(tokenBalance, totalFee);
        }

        s_state = State.Resolved;
        emit Resolved(i_buyer, i_seller);

        if (buyerAward > 0) {
            i_tokenContract.safeTransfer(i_buyer, buyerAward);
        }
        if (i_arbiterFee > 0) {
            i_tokenContract.safeTransfer(i_arbiter, i_arbiterFee);
        }
        tokenBalance = i_tokenContract.balanceOf(address(this));
        if (tokenBalance > 0) {
            i_tokenContract.safeTransfer(i_seller, tokenBalance);
        }
    }

    /////////////////////
    // View functions
    /////////////////////

    function getPrice() external view returns (uint256) {
        return i_price;
    }

    function getTokenContract() external view returns (IERC20) {
        return i_tokenContract;
    }

    function getBuyer() external view returns (address) {
        return i_buyer;
    }

    function getSeller() external view returns (address) {
        return i_seller;
    }

    function getArbiter() external view returns (address) {
        return i_arbiter;
    }

    function getArbiterFee() external view returns (uint256) {
        return i_arbiterFee;
    }

    function getState() external view returns (State) {
        return s_state;
    }
}
