// Counter and token state changes are ordered EVM transactions. The constructor
// writes initial storage before runtime code is installed; a reverted transfer
// restores its balance writes and emits no Transfer log.
//
// deploy -> read -> transfer or revert
// Balances and counter values fit uint256; these fixtures use no precompiles.
// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

contract Counter {
    uint256 public value;

    /// Initializes the stored counter value.
    constructor(uint256 initialValue) {
        value = initialValue;
    }

    /// Increments the counter by one, reverting on uint256 overflow.
    function increment() external {
        value += 1;
    }
}

contract MinimalToken {
    mapping(address => uint256) private balances;
    event Transfer(address indexed from, address indexed to, uint256 amount);

    /// Mints the supplied amount to the deploying address.
    constructor(uint256 supply) {
        balances[msg.sender] = supply;
        emit Transfer(address(0), msg.sender, supply);
    }

    /// Returns the owner's balance without changing state.
    function balanceOf(address owner) external view returns (uint256) {
        return balances[owner];
    }

    /// Moves tokens to a recipient or reverts with the encoded balance error.
    function transfer(address to, uint256 amount) external returns (bool) {
        require(balances[msg.sender] >= amount, "insufficient balance");
        balances[msg.sender] -= amount;
        balances[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }
}
