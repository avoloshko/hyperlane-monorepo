// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.13;

import "forge-std/Test.sol";

import {IOptimisticIsm} from "../../contracts/interfaces/isms/IOptimisticIsM.sol";
import {StaticOptimisticIsmFactory} from "../../contracts/isms/optimistic/StaticOptimisticIsmFactory.sol";
import {StaticOptimisticIsm} from "../../contracts/isms/optimistic/StaticOptimisticIsm.sol";
import {TestIsm, MOfNTestUtils, MessageUtils} from "./IsmTestUtils.sol";
import "../../contracts/Mailbox.sol";

contract OptimisticIsm is Test {
    struct PreVerifiedMessageData {
        address submodule;
        uint96 timestamp;
    }

    StaticOptimisticIsmFactory factory;
    StaticOptimisticIsm ism;
    bytes metadata;

    function setUp() public {
        factory = new StaticOptimisticIsmFactory();
    }

    function deployOptimisticIsmWithWatchers(
        uint8 m,
        uint8 n,
        bytes32 seed
    ) internal {
        bytes32 randomness = seed;
        address[] memory watchers = new address[](n);

        for (uint256 i = 0; i < n; i++) {
            randomness = keccak256(abi.encode(randomness));
            address watcher = address(uint160(uint256(randomness)));
            watchers[i] = watcher;
        }

        metadata = abi.encode(randomness);

        ism = StaticOptimisticIsm(factory.deploy(watchers, m));
    }

    function testFactory(
        uint8 m,
        uint8 n,
        bytes32 seed
    ) public {
        vm.assume(0 < m && m <= n && n < 10);

        deployOptimisticIsmWithWatchers(m, n, seed);

        (address[] memory watchers, ) = ism.watchersAndThreshold();

        assertTrue(address(factory.getAddress(watchers, m)) == address(ism));
        assertTrue(address(factory.deploy(watchers, m)) == address(ism));
    }

    function testSetSubmodule(
        uint8 m,
        uint8 n,
        bytes32 seed,
        uint32 origin
    ) public {
        vm.assume(0 < m && m <= n && n < 10);
        deployOptimisticIsmWithWatchers(m, n, seed);

        address newSubmodule = address(new TestIsm(""));

        vm.prank(ism.owner());

        ism.setSubmodule(newSubmodule, origin);

        assertTrue(
            address(ism.submodule(MessageUtils.build(origin))) == newSubmodule
        );
    }

    function testSetSubmodule_revertsWhenNonOwner(
        uint8 m,
        uint8 n,
        bytes32 seed,
        address nonOwner,
        uint32 origin
    ) public {
        vm.assume(0 < m && m <= n && n < 10);
        deployOptimisticIsmWithWatchers(m, n, seed);

        vm.assume(nonOwner != ism.owner());

        address newSubmodule = address(new TestIsm(""));
        vm.prank(nonOwner);
        vm.expectRevert(bytes("Ownable: caller is not the owner"));

        ism.setSubmodule(newSubmodule, origin);
    }

    function testSetFraudWindow(
        uint8 m,
        uint8 n,
        bytes32 seed,
        uint32 fraudWindow
    ) public {
        vm.assume(0 < m && m <= n && n < 10);
        vm.assume(0 < fraudWindow);
        deployOptimisticIsmWithWatchers(m, n, seed);

        vm.prank(ism.owner());

        ism.setFraudWindow(fraudWindow);

        assertTrue(ism.fraudWindow() == fraudWindow);
    }

    function testSetFraudWindow_revertsWhenNonOwner(
        uint8 m,
        uint8 n,
        bytes32 seed,
        address nonOwner,
        uint32 fraudWindow
    ) public {
        vm.assume(0 < m && m <= n && n < 10);
        vm.assume(fraudWindow > 0);
        deployOptimisticIsmWithWatchers(m, n, seed);

        vm.assume(nonOwner != ism.owner());

        vm.prank(nonOwner);
        vm.expectRevert(bytes("Ownable: caller is not the owner"));

        ism.setFraudWindow(1);
    }

    function testSetFraudWindow_revertsWhenNonPositiveFraudWindowIsPassed(
        uint8 m,
        uint8 n,
        bytes32 seed,
        uint32 fraudWindow
    ) public {
        vm.assume(0 < m && m <= n && n < 10);
        vm.assume(fraudWindow == 0);
        deployOptimisticIsmWithWatchers(m, n, seed);

        vm.prank(ism.owner());
        vm.expectRevert(bytes("fraudWindow must be positive"));

        ism.setFraudWindow(fraudWindow);
    }

    function testMarkFraudulent(
        uint8 m,
        uint8 n,
        bytes32 seed,
        uint32 watcherIndex
    ) public {
        vm.assume(0 < m && m <= n && n < 10);
        deployOptimisticIsmWithWatchers(m, n, seed);

        address submodule = address(new TestIsm(""));

        (address[] memory watchers, ) = ism.watchersAndThreshold();

        vm.assume(0 < watcherIndex && watcherIndex < watchers.length);

        address watcher = watchers[watcherIndex];

        vm.prank(watcher);

        ism.markFraudulent(submodule);

        assertTrue(ism.hasMarkedFraudulent(watcher, submodule));
        assertTrue(ism.fraudulentCount(submodule) == 1);
    }

    function testMarkFraudulentTwice(
        uint8 m,
        uint8 n,
        bytes32 seed,
        uint32 watcher1Index
    ) public {
        vm.assume(0 < m && m <= n && n < 10);
        deployOptimisticIsmWithWatchers(m, n, seed);

        address submodule = address(new TestIsm(""));

        (address[] memory watchers, ) = ism.watchersAndThreshold();

        vm.assume(0 < watcher1Index && watcher1Index < watchers.length);
        uint32 watcher2Index = watcher1Index + 1;
        if (watcher2Index == watchers.length) {
            watcher2Index = watcher1Index - 1;
        }

        address watcher1 = watchers[watcher1Index];
        address watcher2 = watchers[watcher2Index];

        vm.prank(watcher1);

        ism.markFraudulent(submodule);

        vm.prank(watcher2);

        ism.markFraudulent(submodule);

        assertTrue(ism.hasMarkedFraudulent(watcher1, submodule));
        assertTrue(ism.hasMarkedFraudulent(watcher2, submodule));
        assertTrue(ism.fraudulentCount(submodule) == 2);
    }

    function testMarkFraudulent_revertsWhenNonWatcher(
        uint8 m,
        uint8 n,
        bytes32 seed,
        address notWatcher
    ) public {
        vm.assume(0 < m && m <= n && n < 10);
        deployOptimisticIsmWithWatchers(m, n, seed);

        address submodule = address(new TestIsm(""));

        vm.prank(notWatcher);
        vm.expectRevert(bytes("caller is not the watcher"));

        ism.markFraudulent(submodule);
    }

    function testMarkFraudulent_revertsWhenMarkedTwiceByTheSameWatcher(
        uint8 m,
        uint8 n,
        bytes32 seed,
        uint32 watcherIndex
    ) public {
        vm.assume(0 < m && m <= n && n < 10);
        deployOptimisticIsmWithWatchers(m, n, seed);

        address submodule = address(new TestIsm(""));

        (address[] memory watchers, ) = ism.watchersAndThreshold();

        vm.assume(0 < watcherIndex && watcherIndex < watchers.length);

        address watcher = watchers[watcherIndex];

        vm.prank(watcher);

        ism.markFraudulent(submodule);

        vm.prank(watcher);
        vm.expectRevert(bytes("already marked as fraudulent"));

        ism.markFraudulent(submodule);
    }

    function testPreVerify(
        uint8 m,
        uint8 n,
        bytes32 seed,
        uint32 origin,
        uint32 blockTimestamp,
        bytes memory body
    ) public {
        vm.assume(0 < m && m <= n && n < 10);
        deployOptimisticIsmWithWatchers(m, n, seed);

        address newSubmodule = address(new TestIsm(metadata));
        vm.prank(ism.owner());
        ism.setSubmodule(newSubmodule, origin);

        bytes memory message = abi.encodePacked(
            uint8(0),
            uint32(0),
            uint32(origin),
            bytes32(0),
            uint32(0),
            bytes32(0),
            body
        );

        vm.warp(blockTimestamp);
        assertTrue(ism.preVerify(metadata, message));

        (address submodule, uint96 timestamp) = ism.preVerifiedMessageData(
            Message.id(message)
        );

        assertTrue(submodule == newSubmodule);
        assertTrue(blockTimestamp == timestamp);
    }

    function testPreVerify_revertsWhenSubmoduleFailsToVerify(
        uint8 m,
        uint8 n,
        bytes32 seed,
        uint32 origin,
        bytes memory body
    ) public {
        vm.assume(0 < m && m <= n && n < 10);
        deployOptimisticIsmWithWatchers(m, n, seed);

        address newSubmodule = address(new TestIsm(""));
        vm.prank(ism.owner());
        ism.setSubmodule(newSubmodule, origin);

        vm.expectRevert(bytes("message does not pass pre-verification"));
        ism.preVerify(
            metadata,
            abi.encodePacked(
                uint8(0),
                uint32(0),
                uint32(origin),
                bytes32(0),
                uint32(0),
                bytes32(0),
                body
            )
        );
    }

    function testPreVerify_revertsWhenMessageHasAlreadyBeenPreVerified(
        uint8 m,
        uint8 n,
        bytes32 seed,
        uint32 origin,
        bytes memory body
    ) public {
        vm.assume(0 < m && m <= n && n < 10);
        deployOptimisticIsmWithWatchers(m, n, seed);

        address newSubmodule = address(new TestIsm(metadata));
        vm.prank(ism.owner());
        ism.setSubmodule(newSubmodule, origin);

        bytes memory message = abi.encodePacked(
            uint8(0),
            uint32(0),
            uint32(origin),
            bytes32(0),
            uint32(0),
            bytes32(0),
            body
        );

        assertTrue(ism.preVerify(metadata, message));

        vm.expectRevert(bytes("message has already been pre-verified"));
        ism.preVerify(metadata, message);
    }

    function testVerify(
        uint8 m,
        uint8 n,
        bytes32 seed,
        uint32 origin,
        uint32 blockTimestamp,
        uint32 fraudWindow
    ) public {
        vm.assume(0 < m && m <= n && n < 10);
        vm.assume(0 < fraudWindow && fraudWindow < 100000);
        vm.assume(0 < blockTimestamp && blockTimestamp < 100000);
        deployOptimisticIsmWithWatchers(m, n, seed);

        address newSubmodule = address(new TestIsm(metadata));
        vm.prank(ism.owner());
        ism.setSubmodule(newSubmodule, origin);

        vm.prank(ism.owner());
        ism.setFraudWindow(fraudWindow);

        bytes memory message = abi.encodePacked(
            uint8(0),
            uint32(0),
            uint32(origin),
            bytes32(0),
            uint32(0),
            bytes32(0),
            ""
        );

        vm.warp(blockTimestamp);
        assertTrue(ism.preVerify(metadata, message));

        vm.warp(blockTimestamp + fraudWindow + 1);
        assertTrue(ism.verify("", message));
    }

    function testVerify_revertsWhenFraudWindowHasNotPassed(
        uint8 m,
        uint8 n,
        bytes32 seed,
        uint32 origin,
        uint96 blockTimestamp,
        uint32 fraudWindow
    ) public {
        vm.assume(0 < m && m <= n && n < 10);
        vm.assume(0 < fraudWindow && fraudWindow < 100000);
        vm.assume(0 < blockTimestamp && blockTimestamp < 100000);
        deployOptimisticIsmWithWatchers(m, n, seed);

        address newSubmodule = address(new TestIsm(metadata));
        vm.prank(ism.owner());
        ism.setSubmodule(newSubmodule, origin);

        vm.prank(ism.owner());
        ism.setFraudWindow(fraudWindow);

        bytes memory message = abi.encodePacked(
            uint8(0),
            uint32(0),
            uint32(origin),
            bytes32(0),
            uint32(0),
            bytes32(0),
            ""
        );

        vm.warp(blockTimestamp);
        assertTrue(ism.preVerify(metadata, message));

        vm.warp(blockTimestamp + fraudWindow);

        vm.expectRevert(bytes("fraudWindow has not passed yet"));
        ism.verify("", message);
    }

    function testVerify_revertsWhenMessageHasNotBeenPreVerified(
        uint8 m,
        uint8 n,
        bytes32 seed,
        uint32 origin,
        uint32 blockTimestamp,
        uint32 fraudWindow
    ) public {
        vm.assume(0 < m && m <= n && n < 10);
        vm.assume(0 < fraudWindow && fraudWindow < 100000);
        vm.assume(0 < blockTimestamp && blockTimestamp < 100000);
        deployOptimisticIsmWithWatchers(m, n, seed);

        address newSubmodule = address(new TestIsm(metadata));
        vm.prank(ism.owner());
        ism.setSubmodule(newSubmodule, origin);

        vm.prank(ism.owner());
        ism.setFraudWindow(fraudWindow);

        bytes memory message = abi.encodePacked(
            uint8(0),
            uint32(0),
            uint32(origin),
            bytes32(0),
            uint32(0),
            bytes32(0),
            ""
        );

        vm.warp(blockTimestamp + fraudWindow + 1);

        vm.expectRevert(bytes("message has not been pre-verified"));
        ism.verify("", message);
    }

    function testVerify_revertsWhenSubmoduleIsFraudulent(
        uint8 m,
        uint8 n,
        bytes32 seed,
        uint32 origin,
        uint32 blockTimestamp,
        uint32 fraudWindow
    ) public {
        vm.assume(0 < m && m <= n && n < 10);
        vm.assume(0 < fraudWindow && fraudWindow < 100000);
        vm.assume(0 < blockTimestamp && blockTimestamp < 100000);
        deployOptimisticIsmWithWatchers(m, n, seed);

        address newSubmodule = address(new TestIsm(metadata));
        vm.prank(ism.owner());
        ism.setSubmodule(newSubmodule, origin);

        (address[] memory watchers, uint8 threshold) = ism
            .watchersAndThreshold();

        for (uint8 i = 0; i < threshold; ++i) {
            vm.prank(watchers[i]);
            ism.markFraudulent(newSubmodule);
        }

        bytes memory message = abi.encodePacked(
            uint8(0),
            uint32(0),
            uint32(origin),
            bytes32(0),
            uint32(0),
            bytes32(0),
            ""
        );

        vm.warp(blockTimestamp);
        ism.preVerify(metadata, message);

        vm.warp(blockTimestamp + fraudWindow + 1);
        vm.expectRevert(bytes("pre-verification submodule is fraudulent"));
        ism.verify("", message);
    }
}
