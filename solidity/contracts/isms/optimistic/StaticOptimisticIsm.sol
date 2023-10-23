// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.0;

// ============ Internal Imports ============
import {AbstractOptimisticIsm} from "./AbstractOptimisticIsm.sol";
import {AggregationIsmMetadata} from "../../libs/isms/AggregationIsmMetadata.sol";
import {MetaProxy} from "../../libs/MetaProxy.sol";
import "../aggregation/AbstractAggregationIsm.sol";

/**
 * @title StaticAggregationIsm
 * @notice Manages per-domain m-of-n ISM sets that are used to verify interchain messages
 */
contract StaticOptimisticIsm is AbstractOptimisticIsm {
    // ============ Public Functions ============

    /**
     * @notice Returns the set of watchers responsible for marking fraudulent submodules and the threshold
     * @return watchers The array of addresses
     * @return threshold The number of ISMs needed to verify
     */
    function watchersAndThreshold()
        internal
        pure
        override
        returns (address[] memory, uint8)
    {
        return abi.decode(MetaProxy.metadata(), (address[], uint8));
    }
}
