// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test, console} from "forge-std/Test.sol";
import {JSONDecoder} from "./JSONDecoder.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {Proxy} from "@optimism/src/universal/Proxy.sol";
import {ZKL2OutputOracle} from "src/ZKL2OutputOracle.sol";

contract Utils is Test, JSONDecoder {
    function deployWithConfig(Config memory cfg) public returns (address) {
        address zkL2OutputOracleImpl = address(new ZKL2OutputOracle());
        cfg.l2OutputOracleProxy = address(new Proxy(address(this)));

        // Upgrade the proxy to point to the implementation and call initialize().
        // Override the starting output root and timestmp with the passed values.
        upgradeAndInitialize(zkL2OutputOracleImpl, cfg, address(0));

        // Transfer ownership of proxy to owner specified in the config.
        Proxy(payable(cfg.l2OutputOracleProxy)).changeAdmin(cfg.owner);

        return cfg.l2OutputOracleProxy;
    }

    function upgradeAndInitialize(
        address impl,
        Config memory cfg,
        address _spoofedAdmin
    ) public {
        // require that the verifier gateway is deployed
        require(
            address(cfg.verifierGateway).code.length > 0,
            "ZKUpgrader: verifier gateway not deployed"
        );

        ZKL2OutputOracle.ZKInitParams memory zkInitParams = ZKL2OutputOracle
            .ZKInitParams({
                chainId: cfg.chainId,
                verifierGateway: cfg.verifierGateway,
                vkey: cfg.vkey,
                owner: cfg.owner,
                startingOutputRoot: cfg.startingOutputRoot,
                rollupConfigHash: cfg.rollupConfigHash
            });

        // If we are spoofing the admin (used in testing), start prank.
        if (_spoofedAdmin != address(0)) vm.startPrank(_spoofedAdmin);

        Proxy(payable(cfg.l2OutputOracleProxy)).upgradeToAndCall(
            impl,
            abi.encodeCall(
                ZKL2OutputOracle.initialize,
                (
                    cfg.submissionInterval,
                    cfg.l2BlockTime,
                    cfg.startingBlockNumber,
                    cfg.startingTimestamp,
                    cfg.proposer,
                    cfg.challenger,
                    cfg.finalizationPeriod,
                    zkInitParams
                )
            )
        );
    }

    function readJson(
        string memory filepath
    ) public view returns (Config memory) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/", filepath);
        string memory json = vm.readFile(path);
        bytes memory data = vm.parseJson(json);
        return abi.decode(data, (Config));
    }

    function readJsonWithRPCFromEnv(
        string memory filepath
    ) public view returns (Config memory) {
        Config memory config = readJson(filepath);
        return config;
    }

    function fetchOutputRoot(
        Config memory config
    ) public returns (bytes32 startingOutputRoot, uint256 startingTimestamp) {
        string memory hexStartingBlockNumber = createHexString(
            config.startingBlockNumber
        );

        string memory l2NodeRpc = vm.envString("L2_NODE_RPC");

        string[] memory inputs = new string[](6);
        inputs[0] = "cast";
        inputs[1] = "rpc";
        inputs[2] = "--rpc-url";
        // TODO: Reading the env in this way doesn't work. Need to load it in another way.
        inputs[3] = l2NodeRpc;
        inputs[4] = "optimism_outputAtBlock";
        inputs[5] = hexStartingBlockNumber;

        string memory jsonRes = string(vm.ffi(inputs));
        bytes memory outputRootBytes = vm.parseJson(jsonRes, ".outputRoot");
        bytes memory startingTimestampBytes = vm.parseJson(
            jsonRes,
            ".blockRef.timestamp"
        );

        startingOutputRoot = abi.decode(outputRootBytes, (bytes32));
        startingTimestamp = abi.decode(startingTimestampBytes, (uint256));
    }

    // This script updates the rollup config hash and the block number in the config.
    function updateRollupConfig() public {
        // Build the fetch-rollup-config binary.
        string[] memory inputs = new string[](6);
        inputs[0] = "cargo";
        inputs[1] = "build";
        inputs[2] = "--bin";
        inputs[3] = "fetch-rollup-config";
        inputs[4] = "--release";
        inputs[5] = "--quiet";
        vm.ffi(inputs);

        // Run the fetch-rollup-config binary which updates the rollup config hash and the block number in the config.
        string[] memory inputs2 = new string[](6);
        inputs2[0] = "cargo";
        inputs2[1] = "run";
        inputs2[2] = "--bin";
        inputs2[3] = "fetch-rollup-config";
        inputs2[4] = "--release";
        inputs2[5] = "--quiet";

        vm.ffi(inputs2);
    }

    function createHexString(
        uint256 value
    ) public pure returns (string memory) {
        string memory hexStartingBlockNum = Strings.toHexString(value);
        bytes memory startingBlockNumAsBytes = bytes(hexStartingBlockNum);
        require(
            startingBlockNumAsBytes.length >= 4 &&
                startingBlockNumAsBytes[0] == "0" &&
                startingBlockNumAsBytes[1] == "x",
            "Invalid input"
        );

        if (startingBlockNumAsBytes[2] == "0") {
            bytes memory result = new bytes(startingBlockNumAsBytes.length - 1);
            result[0] = "0";
            result[1] = "x";
            for (uint256 i = 3; i < startingBlockNumAsBytes.length; i++) {
                result[i - 1] = startingBlockNumAsBytes[i];
            }
            return string(result);
        }
        return hexStartingBlockNum;
    }
}
