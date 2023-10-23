// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.0;

// ============ External Imports ============
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

// ============ Internal Imports ============
import {IInterchainSecurityModule} from "../../interfaces/IInterchainSecurityModule.sol";
import {IOptimisticIsm} from "../../interfaces/isms/IOptimisticIsm.sol";
import "../../Mailbox.sol";

/**
 * @title AbstractOptimisticIsm
 * @notice Manages message verification for interchain communication using an optimistic approach
 */
abstract contract AbstractOptimisticIsm is IOptimisticIsm, Ownable {
    // ============ Constants ============

    // solhint-disable-next-line const-name-snakecase
    uint8 public constant moduleType =
        uint8(IInterchainSecurityModule.Types.OPTIMISTIC);

    // ============ Virtual Functions ============
    // ======= OVERRIDE THESE TO IMPLEMENT =======

    /**
     * @dev Gets the watchers and the threshold
     * @return watchers An array of watcher addresses
     * @return threshold The threshold value
     */
    function watchersAndThreshold()
        internal
        pure
        virtual
        returns (address[] memory watchers, uint8 threshold);

    // ============ Events ============

    /**
     * @notice Emitted when the fraud window duration is set
     * @param fraudWindow The new duration of the fraud window
     */
    event FraudWindowSet(uint256 fraudWindow);

    /**
     * @notice Emitted when a submodule is assigned to a specific message origin
     * @param submodule The address of the submodule
     * @param origin The origin of the messages the submodule is responsible for
     */
    event SubmoduleSet(address submodule, uint32 origin);

    /**
     * @notice Emitted when a message is pre-verified
     * @dev messageId is not indexed to save gas. Set it to indexed if there will be look ups by messageId.
     * @param messageId The unique identifier of the pre-verified message
     * @param submodule The address of the submodule that pre-verified the message
     * @param timestamp The block timestamp when the message was pre-verified
     */
    event MessagePreVerified(
        bytes32 messageId,
        address submodule,
        uint256 timestamp
    );

    // ============= Structs =============

    struct PreVerifiedMessageData {
        // Maximize the efficiency of storage per message verification to be accommodated within a total of 32 bytes
        address submodule;
        uint96 timestamp;
    }

    // ============ Mutable Storage ============

    // Mapping to keep track of which watcher has marked a submodule as fraudulent
    mapping(address => mapping(address => bool)) public hasMarkedFraudulent;

    // Mapping to keep track of how many times a submodule has been marked as fraudulent
    mapping(address => uint256) public fraudulentCount;

    // Mapping to store pre-verified messages along with submodule
    mapping(bytes32 => PreVerifiedMessageData) public preVerifiedMessageData;

    // Mapping to store submodules per message origin
    mapping(uint32 => IInterchainSecurityModule) public submodules;

    // The duration of the fraud window
    uint256 public fraudWindow;

    // ============ Modifiers ============

    /**
     * @notice Ensures function access is restricted to authorized watchers
     * @dev This is a less optimized O(n) lookup, but is acceptable due to its rare usage and small watcher list
     */
    modifier onlyWatcher() {
        (address[] memory _watchers, ) = watchersAndThreshold();

        bool found = false;
        for (uint256 i = 0; i < _watchers.length; ) {
            if (_watchers[i] == msg.sender) {
                found = true;
                break;
            }

            // Optimize gas
            unchecked {
                ++i;
            }
        }

        require(found, "caller is not the watcher");

        _;
    }

    // ============ Public Functions ============

    /**
     * @notice Retrieves the current submodule designated for message verification
     * @dev The submodule can vary based on the content or context of the message being processed
     * @param _message Formatted Hyperlane message whose corresponding submodule is to be retrieved
     * @return module The ISM instance that should be used to verify the provided message
     */
    function submodule(bytes calldata _message)
        external
        view
        returns (IInterchainSecurityModule)
    {
        uint32 _origin = Message.origin(_message);

        return submodules[_origin];
    }

    /**
     * @notice Verifies a message after it has passed the fraud window period
     * @param _message The interchain message
     * @return True if the verification is successful, otherwise false
     */
    function verify(bytes calldata, bytes calldata _message)
        external
        returns (bool)
    {
        bytes32 _id = Message.id(_message);

        PreVerifiedMessageData memory _data = preVerifiedMessageData[_id];

        require(_data.timestamp > 0, "message has not been pre-verified");
        require(
            _data.timestamp + fraudWindow < block.timestamp,
            "fraudWindow has not passed yet"
        );

        (, uint8 _threshold) = watchersAndThreshold();

        require(
            fraudulentCount[_data.submodule] < _threshold,
            "pre-verification submodule is fraudulent"
        );

        // Can release some gas now as as Mailbox contract keeps a list of delivered messages
        delete preVerifiedMessageData[_id];

        return true;
    }

    /**
     * @notice Initiates the pre-verification of interchain messages using the configured submodule
     * @dev This function should be called before the main verification
     * @param _message Hyperlane encoded interchain message
     * @return True if the message successfully passes the pre-verification
     */
    function preVerify(bytes calldata _metadata, bytes calldata _message)
        external
        returns (bool)
    {
        bytes32 _id = Message.id(_message);
        uint32 _origin = Message.origin(_message);

        IInterchainSecurityModule _submodule = submodules[_origin];

        require(
            preVerifiedMessageData[_id].timestamp == 0,
            "message has already been pre-verified"
        );

        preVerifiedMessageData[_id] = PreVerifiedMessageData({
            submodule: address(_submodule),
            timestamp: uint96(block.timestamp)
        });

        require(
            _submodule.verify(_metadata, _message),
            "message does not pass pre-verification"
        );

        emit MessagePreVerified(_id, address(_submodule), block.timestamp);

        return true;
    }

    /**
     * @notice Marks a submodule as fraudulent
     * @param _submodule The address of the submodule to mark as fraudulent
     */
    function markFraudulent(address _submodule) external override onlyWatcher {
        require(
            !hasMarkedFraudulent[msg.sender][_submodule],
            "already marked as fraudulent"
        );

        // Mark that the sender has now marked this submodule as fraudulent
        hasMarkedFraudulent[msg.sender][_submodule] = true;

        // Increment the fraudulent count for this submodule
        fraudulentCount[_submodule] += 1;
    }

    /**
     * @notice Sets the duration of the fraud window
     * @param _fraudWindow The new duration of the fraud window
     */
    function setFraudWindow(uint256 _fraudWindow) external onlyOwner {
        require(_fraudWindow > 0, "fraudWindow must be positive");

        fraudWindow = _fraudWindow;

        emit FraudWindowSet(_fraudWindow);
    }

    /**
     * @notice Assigns a submodule to a specific message origin
     * @param _submodule The address of the submodule
     * @param _origin The origin of the messages the submodule is responsible for
     */
    function setSubmodule(address _submodule, uint32 _origin)
        external
        onlyOwner
    {
        submodules[_origin] = IInterchainSecurityModule(_submodule);

        emit SubmoduleSet(_submodule, _origin);
    }
}
