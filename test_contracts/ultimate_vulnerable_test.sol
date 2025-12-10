// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * ULTIMATE VULNERABILITY TEST CONTRACT
 * Contains ALL vulnerability patterns from valurnabilities.txt and our enhanced patterns
 * 
 * ⚠️ WARNING: This contract is INTENTIONALLY VULNERABLE for testing purposes
 * Contains 25+ categories of non-privileged fund-drain vulnerabilities
 */

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
}

contract UltimateVulnerableTestContract {
    // ============= STORAGE LAYOUT FOR TESTING =============
    address public owner;                    // Slot 0 - Should be initialized
    uint256 public totalSupply;             // Slot 1 - Balance tracking
    uint256 public totalShares;             // Slot 2 - Share calculations
    uint256 public rewardIndex;             // Slot 3 - Reward distribution
    address public rewardToken;             // Slot 4 - Should not be zero
    uint256 public feeRate;                 // Slot 5 - Fee calculations
    bool public paused;                     // Slot 6 - State control
    address public treasury;                // Slot 7 - Should be initialized
    
    mapping(address => uint256) public balances;        // Slot 8
    mapping(address => uint256) public shares;          // Slot 9
    mapping(address => uint256) public userRewardIndex; // Slot 10
    mapping(address => uint256) public rewards;         // Slot 11
    mapping(address => bool) public admins;             // Slot 12
    mapping(address => mapping(address => uint256)) public allowances; // Slot 13
    
    uint256[] public tokenIds;              // Slot 14 - Array manipulation
    
    // Events for testing
    event Deposit(address indexed user, uint256 amount);
    event Withdraw(address indexed user, uint256 amount);
    event RewardClaimed(address indexed user, uint256 amount);
    
    // ============= VULNERABILITY CATEGORY 1: UNINITIALIZED CONTRACT =============
    
    // VULN 1: Constructor missing critical initialization
    constructor() {
        // ❌ CRITICAL: Missing owner initialization (remains address(0))
        // ❌ CRITICAL: Missing treasury initialization 
        // ❌ CRITICAL: Missing rewardToken initialization
        // Should initialize: owner = msg.sender, treasury, rewardToken
    }
    
    // VULN 2: Public initialize function without initializer modifier
    function initialize(address _owner, address _treasury) public {
        // ❌ HIGH: Can be called multiple times
        // ❌ HIGH: No initializer modifier protection
        owner = _owner;
        treasury = _treasury;
        // Missing _disableInitializers() for proxy compatibility
    }
    
    // ============= VULNERABILITY CATEGORY 2: UNINITIALIZED STORAGE =============
    
    // VULN 3: Zero oracle/price leads to free mints
    function mintWithPrice(uint256 amount) public {
        // ❌ CRITICAL: If priceOracle = 0, user gets infinite tokens
        uint256 price = getPriceFromOracle(); // Returns 0 if uninitialized
        require(msg.value >= amount * price, "Insufficient payment");
        balances[msg.sender] += amount;
        totalSupply += amount;
    }
    
    function getPriceFromOracle() public view returns (uint256) {
        // ❌ CRITICAL: Returns 0 if rewardToken address is zero
        if (rewardToken == address(0)) return 0; // Uninitialized oracle
        return 1 ether; // Normal price
    }
    
    // VULN 4: Zero share ratio leads to infinite shares
    function deposit(uint256 amount) public {
        // ❌ CRITICAL: If totalSupply = 0, division by zero or infinite shares
        uint256 sharesToMint = (totalShares == 0) ? amount : amount * totalShares / totalSupply;
        if (totalShares == 0) sharesToMint = amount * 1e18; // ❌ Arbitrary multiplier
        
        shares[msg.sender] += sharesToMint;
        totalShares += sharesToMint;
        balances[msg.sender] += amount;
        totalSupply += amount;
        
        emit Deposit(msg.sender, amount);
    }
    
    // ============= VULNERABILITY CATEGORY 3: REENTRANCY =============
    
    // VULN 5: Classic single-function reentrancy
    function withdrawAll() public {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "No balance");
        
        // ❌ CRITICAL: External call before state update (CEI violation)
        payable(msg.sender).transfer(balance);
        balances[msg.sender] = 0; // ❌ State updated AFTER external call
        totalSupply -= balance;
        
        emit Withdraw(msg.sender, balance);
    }
    
    // VULN 6: Cross-function reentrancy
    mapping(address => bool) private withdrawing;
    
    function startWithdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        withdrawing[msg.sender] = true;
        
        // ❌ HIGH: External call while state is inconsistent
        (bool success,) = msg.sender.call("");
        require(success, "Callback failed");
        
        // Can be re-entered here to call completeWithdraw
    }
    
    function completeWithdraw(uint256 amount) public {
        require(withdrawing[msg.sender], "Not withdrawing");
        // ❌ HIGH: No check if startWithdraw amount matches
        balances[msg.sender] -= amount; 
        withdrawing[msg.sender] = false;
        payable(msg.sender).transfer(amount);
    }
    
    // VULN 7: Read-only reentrancy
    function getExchangeRate() public view returns (uint256) {
        // ❌ MEDIUM: Can be manipulated during reentrancy
        if (totalShares == 0) return 1e18;
        return totalSupply * 1e18 / totalShares;
    }
    
    // ============= VULNERABILITY CATEGORY 4: ARITHMETIC OVERFLOW/UNDERFLOW =============
    
    // VULN 8: Unchecked math operations
    function unsafeMath(uint256 a, uint256 b) public pure returns (uint256) {
        unchecked {
            // ❌ HIGH: Can overflow/underflow
            return a * b + (a - b) * 2;
        }
    }
    
    // VULN 9: Division by zero
    function calculateReward(uint256 amount) public view returns (uint256) {
        // ❌ HIGH: Division by zero if totalStaked = 0
        uint256 totalStaked = totalSupply;
        return amount * rewardIndex / totalStaked; // ❌ No zero check
    }
    
    // VULN 10: Precision loss in calculations
    function convertShares(uint256 shareAmount) public view returns (uint256) {
        // ❌ MEDIUM: Precision loss, rounding errors
        return shareAmount * totalSupply / totalShares / 1000 * 999; // Intentional precision loss
    }
    
    // ============= VULNERABILITY CATEGORY 5: BROKEN ACCESS CONTROL =============
    
    // VULN 11: tx.origin authentication
    function adminWithdraw() public {
        // ❌ CRITICAL: tx.origin can be manipulated
        require(tx.origin == owner, "Not owner");
        payable(msg.sender).transfer(address(this).balance);
    }
    
    // VULN 12: User-controlled beneficiary
    function transferToUser(address beneficiary, uint256 amount) public {
        // ❌ HIGH: User controls beneficiary address
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        balances[beneficiary] += amount; // ❌ Attacker can specify any beneficiary
    }
    
    // VULN 13: Always true/false conditions
    function checkAccess() public view returns (bool) {
        // ❌ MEDIUM: Always returns false due to uninitialized owner
        return msg.sender == owner; // owner is address(0)
    }
    
    // ============= VULNERABILITY CATEGORY 6: DELEGATECALL MISUSE =============
    
    // VULN 14: Arbitrary delegatecall
    function proxyCall(address target, bytes memory data) public {
        // ❌ CRITICAL: Arbitrary delegatecall allows storage hijacking
        (bool success,) = target.delegatecall(data);
        require(success, "Delegatecall failed");
    }
    
    // VULN 15: Library delegatecall without validation
    function callLibrary(address lib, bytes4 selector, bytes memory data) public {
        // ❌ HIGH: No validation of library address
        bytes memory callData = abi.encodePacked(selector, data);
        (bool success,) = lib.delegatecall(callData);
        require(success, "Library call failed");
    }
    
    // ============= VULNERABILITY CATEGORY 7: UNPROTECTED SELFDESTRUCT =============
    
    // VULN 16: Selfdestruct without protection
    function emergencyDestruct() public {
        // ❌ CRITICAL: No access control
        selfdestruct(payable(msg.sender));
    }
    
    // VULN 17: Selfdestruct with weak condition
    function conditionalDestruct(bool emergency) public {
        // ❌ HIGH: User-controlled condition
        if (emergency) {
            selfdestruct(payable(owner)); // owner is address(0)
        }
    }
    
    // ============= VULNERABILITY CATEGORY 8: WITHDRAWAL ACCOUNTING =============
    
    // VULN 18: Wrong denominator in share calculation
    function withdrawShares(uint256 shareAmount) public {
        require(shares[msg.sender] >= shareAmount, "Insufficient shares");
        
        // ❌ CRITICAL: Should use totalShares, not totalSupply
        uint256 withdrawAmount = shareAmount * totalSupply / totalSupply; // Wrong denominator
        
        shares[msg.sender] -= shareAmount;
        balances[msg.sender] -= withdrawAmount;
        payable(msg.sender).transfer(withdrawAmount);
    }
    
    // VULN 19: Stale totalShares usage
    function redeemShares(uint256 shareAmount) public {
        // ❌ CRITICAL: Uses stale totalShares before update
        uint256 assetAmount = shareAmount * totalSupply / totalShares;
        
        payable(msg.sender).transfer(assetAmount); // Transfer before state update
        shares[msg.sender] -= shareAmount;
        totalShares -= shareAmount; // ❌ Updated too late
    }
    
    // VULN 20: Double-counting in withdrawal
    function withdrawWithBonus(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // ❌ CRITICAL: User balance counted twice
        uint256 bonus = balances[msg.sender] / 10; // Bonus based on balance
        uint256 totalWithdraw = amount + bonus + balances[msg.sender] / 100; // Double counting
        
        balances[msg.sender] -= amount; // Only deduct amount, not bonus
        payable(msg.sender).transfer(totalWithdraw);
    }
    
    // ============= VULNERABILITY CATEGORY 9: PRICE ORACLE MANIPULATION =============
    
    // VULN 21: Single DEX pair price source
    address public priceFeed;
    
    function getPrice() public view returns (uint256) {
        // ❌ HIGH: Single source, can be manipulated
        return IUniswapPair(priceFeed).getReserves0() * 1e18 / IUniswapPair(priceFeed).getReserves1();
    }
    
    function buyWithOracle(uint256 tokenAmount) public payable {
        uint256 price = getPrice(); // ❌ Manipulable price
        require(msg.value >= tokenAmount * price, "Insufficient payment");
        balances[msg.sender] += tokenAmount;
    }
    
    // ============= VULNERABILITY CATEGORY 10: FLASH LOAN EXPLOITS =============
    
    // VULN 22: Reward snapshot before balance update
    function flashDeposit(uint256 amount) public {
        // ❌ CRITICAL: Take snapshot before balance actually changes
        uint256 oldReward = calculatePendingRewards(msg.sender);
        
        // Simulate flash loan deposit
        balances[msg.sender] += amount;
        totalSupply += amount;
        
        // Update user reward based on new balance
        rewards[msg.sender] = calculatePendingRewards(msg.sender); // ❌ Inflated rewards
        
        // Flash loan would be repaid here, but rewards already calculated
    }
    
    function calculatePendingRewards(address user) public view returns (uint256) {
        return balances[user] * rewardIndex / 1e18;
    }
    
    // ============= VULNERABILITY CATEGORY 11: FRONT-RUNNING/MEV =============
    
    // VULN 23: Public rebalance function
    function rebalancePool() public {
        // ❌ HIGH: Public function can be front-run
        uint256 newRatio = address(this).balance * 1e18 / totalSupply;
        if (newRatio > 1.1e18) {
            // Rebalance triggers profit opportunity
            uint256 excess = address(this).balance - totalSupply * 11 / 10;
            payable(msg.sender).transfer(excess); // ❌ Front-runner gets profit
        }
    }
    
    // VULN 24: Migration with exploitable timing
    bool public migrationStarted;
    
    function startMigration() public {
        migrationStarted = true; // ❌ Can be front-run
    }
    
    function migrate(uint256 amount) public {
        require(migrationStarted, "Migration not started");
        // ❌ First migrator might get better rate
        uint256 migrationRate = address(this).balance / totalSupply;
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount * migrationRate);
    }
    
    // ============= VULNERABILITY CATEGORY 12: ERC20 HANDLING =============
    
    // VULN 25: Missing transfer return value check
    function transferTokens(IERC20 token, address to, uint256 amount) public {
        // ❌ HIGH: No return value check
        token.transfer(to, amount);
        balances[to] += amount; // ❌ Assumes transfer succeeded
    }
    
    // VULN 26: Approve race condition
    function approveTokens(IERC20 token, address spender, uint256 amount) public {
        // ❌ MEDIUM: Should reset to 0 first for some tokens
        token.approve(spender, amount);
    }
    
    // VULN 27: Fee-on-transfer token incompatibility
    function depositToken(IERC20 token, uint256 amount) public {
        // ❌ HIGH: Ignores transfer fees
        token.transferFrom(msg.sender, address(this), amount);
        balances[msg.sender] += amount; // ❌ Credits full amount despite fees
        totalSupply += amount;
        // Should use: balanceAfter - balanceBefore
    }
    
    // VULN 28: Arbitrary token address
    function rescueTokens(address token, uint256 amount) public {
        // ❌ CRITICAL: Arbitrary token call - can be malicious contract
        IERC20(token).transfer(msg.sender, amount);
    }
    
    // ============= VULNERABILITY CATEGORY 13: REWARD DISTRIBUTION =============
    
    // VULN 29: Reward index manipulation
    function stake(uint256 amount) public {
        balances[msg.sender] += amount;
        // ❌ HIGH: Should update index BEFORE setting user index
        userRewardIndex[msg.sender] = rewardIndex; // Can be manipulated
        totalSupply += amount;
    }
    
    // VULN 30: Claiming historical rewards
    function claimAllRewards() public {
        // ❌ CRITICAL: No start time consideration - can claim all historical rewards
        uint256 userRewards = balances[msg.sender] * rewardIndex / 1e18;
        rewards[msg.sender] += userRewards;
        
        IERC20(rewardToken).transfer(msg.sender, userRewards);
    }
    
    // VULN 31: Fee calculation without validation
    function setFeeRate(uint256 newFeeRate) public {
        // ❌ HIGH: No validation - can set > 100%
        feeRate = newFeeRate;
    }
    
    function chargeFeesFromDeposit(uint256 amount) public payable {
        uint256 fee = amount * feeRate / 100; // ❌ Can overflow if feeRate > 100
        if (fee > amount) fee = amount * 2; // ❌ Logic error
        payable(treasury).transfer(fee);
        balances[msg.sender] += amount - fee;
    }
    
    // ============= VULNERABILITY CATEGORY 14: INSECURE RANDOMNESS =============
    
    // VULN 32: Predictable randomness
    function lottery() public payable {
        require(msg.value >= 0.1 ether, "Minimum bet");
        
        // ❌ HIGH: Predictable randomness
        uint256 random = uint256(keccak256(abi.encodePacked(
            block.timestamp,    // ❌ Manipulable by miners
            block.difficulty,   // ❌ Predictable
            msg.sender
        ))) % 100;
        
        if (random < 10) { // 10% chance to win
            payable(msg.sender).transfer(address(this).balance);
        }
    }
    
    // ============= VULNERABILITY CATEGORY 15: ARBITRARY EXTERNAL CALLS =============
    
    // VULN 33: User-controlled call target
    function callAnyContract(address target, bytes memory data) public {
        // ❌ CRITICAL: Arbitrary external call
        (bool success, bytes memory result) = target.call(data);
        require(success, "Call failed");
    }
    
    // VULN 34: User-controlled callback
    function withdrawWithCallback(address callbackTarget) public {
        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;
        
        // ❌ HIGH: User controls callback address
        IWithdrawCallback(callbackTarget).onWithdraw(msg.sender, amount);
        payable(msg.sender).transfer(amount);
    }
    
    // ============= VULNERABILITY CATEGORY 16: UNPROTECTED RESCUE FUNCTIONS =============
    
    // VULN 35: Missing access control on rescue
    function rescueETH() public {
        // ❌ CRITICAL: No onlyOwner modifier
        payable(msg.sender).transfer(address(this).balance);
    }
    
    // VULN 36: Wrong condition in rescue
    function rescueTokensConditional(IERC20 token) public {
        // ❌ HIGH: Wrong condition - should check if msg.sender == owner
        require(owner != address(0), "Owner not set"); // ❌ Wrong check
        token.transfer(msg.sender, token.balanceOf(address(this)));
    }
    
    // ============= VULNERABILITY CATEGORY 17: SIGNATURE REPLAY =============
    
    // VULN 37: Missing nonce in permit
    function permitWithoutNonce(address owner, address spender, uint256 value, bytes memory signature) public {
        // ❌ CRITICAL: No nonce protection - signature can be replayed
        bytes32 digest = keccak256(abi.encodePacked(owner, spender, value));
        // Missing: nonce, deadline, domain separator
        
        address recovered = recoverSigner(digest, signature);
        require(recovered == owner, "Invalid signature");
        
        allowances[owner][spender] = value;
    }
    
    function recoverSigner(bytes32 hash, bytes memory signature) internal pure returns (address) {
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }
        return ecrecover(hash, v, r, s);
    }
    
    // ============= VULNERABILITY CATEGORY 18: FALLBACK/RECEIVE LOGIC =============
    
    // VULN 38: State changes in fallback
    fallback() external payable {
        // ❌ MEDIUM: State changes in fallback can be unexpected
        balances[msg.sender] += msg.value;
        totalSupply += msg.value;
        
        // Unexpected token minting through fallback
    }
    
    receive() external payable {
        // ❌ MEDIUM: Automatic processing without checks
        if (msg.value > 1 ether) {
            balances[msg.sender] += msg.value * 2; // ❌ Bonus for large deposits
        }
    }
    
    // ============= VULNERABILITY CATEGORY 19: PRIVILEGE ESCALATION =============
    
    // VULN 39: Unprotected setOwner
    function setOwner(address newOwner) public {
        // ❌ CRITICAL: No access control
        owner = newOwner;
    }
    
    // VULN 40: Unprotected addAdmin
    function addAdmin(address admin) external {
        // ❌ CRITICAL: Anyone can add admins
        admins[admin] = true;
    }
    
    // VULN 41: Direct storage manipulation
    function setStorageSlot(uint256 slot, bytes32 value) public {
        // ❌ CRITICAL: Direct storage overwrite
        assembly {
            sstore(slot, value)
        }
    }
    
    // ============= VULNERABILITY CATEGORY 20: ARRAY MANIPULATION =============
    
    // VULN 42: Unprotected array length manipulation
    function setArrayLength(uint256 newLength) public {
        // ❌ HIGH: Direct array length manipulation
        assembly {
            sstore(tokenIds.slot, newLength)
        }
    }
    
    function popTokenId() public {
        // ❌ MEDIUM: No access control
        tokenIds.pop();
    }
    
    // ============= HELPER INTERFACES =============
    
    // For testing oracle manipulation
    interface IUniswapPair {
        function getReserves0() external view returns (uint256);
        function getReserves1() external view returns (uint256);
    }
    
    interface IWithdrawCallback {
        function onWithdraw(address user, uint256 amount) external;
    }
    
    // ============= ADDITIONAL UTILITY FUNCTIONS =============
    
    function getContractBalance() public view returns (uint256) {
        return address(this).balance;
    }
    
    function getUserBalance(address user) public view returns (uint256) {
        return balances[user];
    }
    
    function getUserShares(address user) public view returns (uint256) {
        return shares[user];
    }
}