// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

import {Script} from "forge-std/Script.sol";
import {EscrowFactory} from "../src/EscrowFactory.sol";
import {Escrow} from "../src/Escrow.sol";

contract DeployEscrowFactory is Script {
    function run() external returns (EscrowFactory) {
        vm.startBroadcast();
        EscrowFactory factory = new EscrowFactory();
        vm.stopBroadcast();
        return factory;
    }
}
