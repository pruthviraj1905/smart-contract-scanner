// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title VulnerableTestContract 
 * @dev INTENTIONALLY VULNERABLE CONTRACT FOR TESTING
 * Contains multiple complex vulnerabilities for scanner validation
 * DO NOT DEPLOY ON MAINNET - FOR TESTING ONLY
 */

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract VulnerableTestContract {
    
    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowances;
    mapping(address => bool) public authorized;
    mapping(address => uint256) public lastWithdrawTime;
    
    address public owner;
    address public feeRecipient;
    uint256 public totalSupply;
    uint256 public withdrawalLimit = 1000 ether;
    uint256 public withdrawalCooldown = 1 days;
    
    bool public emergencyStop = false;
    bool private locked = false;
    
    // Events
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }
    
    modifier nonReentrant() {
        require(!locked, "Reentrant call");
        locked = true;
        _;
        locked = false;
    }
    
    constructor() {
        owner = msg.sender;
        feeRecipient = msg.sender;
        totalSupply = 1000000 ether;
        balances[msg.sender] = totalSupply;
    }
    
    // VULNERABILITY #1: Reentrancy in withdrawal
    function withdrawEther(uint256 amount) public nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        require(amount <= withdrawalLimit, "Exceeds withdrawal limit");
        require(block.timestamp >= lastWithdrawTime[msg.sender] + withdrawalCooldown, "Cooldown active");
        
        lastWithdrawTime[msg.sender] = block.timestamp;
        
        // VULNERABLE: External call before state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        // State update after external call - REENTRANCY VULNERABILITY
        balances[msg.sender] -= amount;
        
        emit Withdrawal(msg.sender, amount);
    }
    
    // VULNERABILITY #2: Public function allows draining any ERC20 token
    function emergencyTokenWithdraw(address token, uint256 amount) public {
        // VULNERABLE: No access control - anyone can call this
        require(!emergencyStop, "Emergency stop active");
        require(amount > 0, "Amount must be greater than zero");
        
        // VULNERABLE: Transfers any token from contract to caller
        IERC20(token).transfer(msg.sender, amount);
    }
    
    // VULNERABILITY #3: Approval manipulation
    function batchApprove(address[] calldata spenders, uint256[] calldata amounts) public {
        require(spenders.length == amounts.length, "Array length mismatch");
        
        for (uint256 i = 0; i < spenders.length; i++) {
            // VULNERABLE: No checks on approval amounts, allows unlimited approvals
            allowances[msg.sender][spenders[i]] = amounts[i];
            emit Approval(msg.sender, spenders[i], amounts[i]);
        }
    }
    
    // VULNERABILITY #4: Integer overflow/underflow (if using older Solidity)
    function unsafeAdd(uint256 a, uint256 b) public pure returns (uint256) {
        // VULNERABLE: In Solidity < 0.8.0, this could overflow
        return a + b;
    }
    
    function unsafeSub(uint256 a, uint256 b) public pure returns (uint256) {
        // VULNERABLE: Could underflow
        return a - b;
    }
    
    // VULNERABILITY #5: Front-running vulnerable auction
    uint256 public currentBid;
    address public highestBidder;
    
    function bid() public payable {
        require(msg.value > currentBid, "Bid too low");
        
        // VULNERABLE: Front-running opportunity
        if (highestBidder != address(0)) {
            // Refund previous bidder
            payable(highestBidder).transfer(currentBid);
        }
        
        currentBid = msg.value;
        highestBidder = msg.sender;
    }
    
    // VULNERABILITY #6: Timestamp manipulation
    function timeBoundedAction() public {
        // VULNERABLE: Miners can manipulate block.timestamp
        require(block.timestamp % 100 == 0, "Wrong timing");
        
        // Give reward
        balances[msg.sender] += 1000 ether;
    }
    
    // VULNERABILITY #7: Unchecked external calls
    function delegateCall(address target, bytes calldata data) public returns (bool success, bytes memory result) {
        // VULNERABLE: Arbitrary delegatecall - can hijack contract state
        require(authorized[msg.sender] || msg.sender == owner, "Not authorized");
        
        (success, result) = target.delegatecall(data);
    }
    
    // VULNERABILITY #8: Gas limit issues
    function massTransfer(address[] calldata recipients, uint256[] calldata amounts) public {
        require(recipients.length == amounts.length, "Array length mismatch");
        
        // VULNERABLE: No gas limit checks, can cause out-of-gas
        for (uint256 i = 0; i < recipients.length; i++) {
            require(balances[msg.sender] >= amounts[i], "Insufficient balance");
            balances[msg.sender] -= amounts[i];
            balances[recipients[i]] += amounts[i];
            emit Transfer(msg.sender, recipients[i], amounts[i]);
        }
    }
    
    // VULNERABILITY #9: Price manipulation oracle
    uint256 public tokenPrice = 1 ether; // Starting price
    
    function updatePrice() public {
        // VULNERABLE: Price can be manipulated by single large transaction
        uint256 contractBalance = address(this).balance;
        uint256 tokenSupplyInContract = balances[address(this)];
        
        if (tokenSupplyInContract > 0) {
            tokenPrice = contractBalance / tokenSupplyInContract;
        }
    }
    
    function buyTokens() public payable {
        require(msg.value > 0, "Must send ETH");
        
        updatePrice(); // Price manipulation opportunity
        
        uint256 tokenAmount = msg.value / tokenPrice;
        require(balances[address(this)] >= tokenAmount, "Insufficient tokens");
        
        balances[address(this)] -= tokenAmount;
        balances[msg.sender] += tokenAmount;
        
        emit Transfer(address(this), msg.sender, tokenAmount);
    }
    
    // VULNERABILITY #10: Unprotected initialization
    bool public initialized = false;
    
    function initialize(address _feeRecipient) public {
        // VULNERABLE: Anyone can call this if not initialized
        require(!initialized, "Already initialized");
        
        feeRecipient = _feeRecipient;
        initialized = true;
        
        // VULNERABLE: Gives caller admin privileges
        authorized[msg.sender] = true;
    }
    
    // VULNERABILITY #11: Logic error in fee calculation
    function transferWithFee(address to, uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // VULNERABLE: Fee calculation error
        uint256 fee = amount / 100; // 1% fee
        uint256 netAmount = amount - fee;
        
        // VULNERABLE: Could transfer more than intended if amount is very small
        if (fee == 0 && amount > 0) {
            fee = 1; // Minimum fee, but this can cause issues
        }
        
        balances[msg.sender] -= amount;
        balances[to] += netAmount;
        balances[feeRecipient] += fee;
        
        emit Transfer(msg.sender, to, netAmount);
        emit Transfer(msg.sender, feeRecipient, fee);
    }
    
    // VULNERABILITY #12: Unprotected selfdestruct
    function destroy() public {
        // VULNERABLE: Only basic check, but authorized mapping can be manipulated
        require(authorized[msg.sender] || msg.sender == owner, "Not authorized");
        
        selfdestruct(payable(msg.sender));
    }
    
    // VULNERABILITY #13: Storage collision in upgradeable pattern
    struct UserData {
        uint256 balance;
        uint256 lastAction;
        bool isVip;
    }
    
    mapping(address => UserData) public userData;
    
    function setUserData(address user, uint256 balance, bool isVip) public {
        // VULNERABLE: No access control
        userData[user].balance = balance;
        userData[user].isVip = isVip;
        userData[user].lastAction = block.timestamp;
    }
    
    // Helper functions for deposits
    receive() external payable {
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }
    
    function deposit() public payable {
        require(msg.value > 0, "Must send ETH");
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }
    
    // View functions
    function balanceOf(address account) public view returns (uint256) {
        return balances[account];
    }
    
    function allowance(address _owner, address spender) public view returns (uint256) {
        return allowances[_owner][spender];
    }
}