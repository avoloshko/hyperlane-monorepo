// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.6.11;

import {IInterchainSecurityModule} from "../IInterchainSecurityModule.sol";

/**
 * @title IOptimisticIsm
 */
interface IOptimisticIsm is IInterchainSecurityModule {
    /**
     * @notice Initiates the pre-verification of interchain messages using the configured submodule
     * @dev This function should be called before the main verification
     * @param _message Hyperlane encoded interchain message
     * @return True if the message successfully passes the pre-verification
     */
    function preVerify(bytes calldata _metadata, bytes calldata _message)
        external
        returns (bool);

    /**
     * @notice Marks a specified submodule as compromised
     * @param _submodule The address of the submodule that is compromised
     */
    function markFraudulent(address _submodule) external;

    /**
     * @notice Retrieves the current submodule designated for message verification
     * @dev The submodule can vary based on the content or context of the message being processed
     * @param _message Formatted Hyperlane message whose corresponding submodule is to be retrieved
     * @return module The ISM instance that should be used to verify the provided message
     */
    function submodule(bytes calldata _message)
        external
        view
        returns (IInterchainSecurityModule);
}
