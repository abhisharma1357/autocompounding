// SPDX-License-Identifier: MIT
pragma solidity =0.8.1;

contract Ownable {
    address private _owner;
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    constructor () {
        _owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }
    function owner() public view virtual returns (address) {
        return _owner;
    }
    modifier onlyOwner() {
        require(owner() == msg.sender, "Ownable: caller is not the owner");
        _;
    }
    function renounceOwnership() public virtual onlyOwner {
        emit OwnershipTransferred(_owner, address(0));
        _owner = address(0);
    }
    function transferOwnership(address newOwner) public virtual onlyOwner {
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }
}

interface IERC20 {
    function name() external view returns (string memory);
    function symbol() external view returns (string memory);
    function decimals() external view returns (uint8);
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address recipient, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);
    function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external;
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
}

interface IPair is IERC20 {
    function token0() external pure returns (address);
    function token1() external pure returns (address);
}

interface IRouter {
    function addLiquidity(address tokenA, address tokenB, uint amountADesired, uint amountBDesired, uint amountAMin, uint amountBMin, address to, uint deadline) external returns (uint amountA, uint amountB, uint liquidity);
    function addLiquidityAVAX(address token, uint amountTokenDesired, uint amountTokenMin, uint amountAVAXMin, address to, uint deadline) external payable returns (uint amountToken, uint amountAVAX, uint liquidity);
    function removeLiquidity(address tokenA, address tokenB, uint liquidity, uint amountAMin, uint amountBMin, address to, uint deadline) external returns (uint amountA, uint amountB);
    function removeLiquidityAVAX(address token, uint liquidity, uint amountTokenMin, uint amountAVAXMin, address to, uint deadline) external returns (uint amountToken, uint amountAVAX);
    function removeLiquidityWithPermit(address tokenA, address tokenB, uint liquidity, uint amountAMin, uint amountBMin, address to, uint deadline, bool approveMax, uint8 v, bytes32 r, bytes32 s) external returns (uint amountA, uint amountB);
    function removeLiquidityAVAXWithPermit(address token, uint liquidity, uint amountTokenMin, uint amountAVAXMin, address to, uint deadline, bool approveMax, uint8 v, bytes32 r, bytes32 s) external returns (uint amountToken, uint amountAVAX);
    function removeLiquidityAVAXSupportingFeeOnTransferTokens(address token, uint liquidity, uint amountTokenMin, uint amountAVAXMin, address to, uint deadline) external returns (uint amountAVAX);
    function removeLiquidityAVAXWithPermitSupportingFeeOnTransferTokens(address token, uint liquidity, uint amountTokenMin, uint amountAVAXMin, address to, uint deadline, bool approveMax, uint8 v, bytes32 r, bytes32 s) external returns (uint amountAVAX);
    function swapExactTokensForTokens(uint amountIn, uint amountOutMin, address[] calldata path, address to, uint deadline) external returns (uint[] memory amounts);
    function swapTokensForExactTokens(uint amountOut, uint amountInMax, address[] calldata path, address to, uint deadline) external returns (uint[] memory amounts);
    function swapExactAVAXForTokens(uint amountOutMin, address[] calldata path, address to, uint deadline) external payable returns (uint[] memory amounts);
    function swapTokensForExactAVAX(uint amountOut, uint amountInMax, address[] calldata path, address to, uint deadline) external returns (uint[] memory amounts);
    function swapExactTokensForAVAX(uint amountIn, uint amountOutMin, address[] calldata path, address to, uint deadline) external returns (uint[] memory amounts);
    function swapAVAXForExactTokens(uint amountOut, address[] calldata path, address to, uint deadline) external payable returns (uint[] memory amounts);
    function swapExactTokensForTokensSupportingFeeOnTransferTokens(uint amountIn, uint amountOutMin, address[] calldata path, address to, uint deadline ) external;
    function swapExactAVAXForTokensSupportingFeeOnTransferTokens( uint amountOutMin, address[] calldata path, address to, uint deadline) external payable;
    function swapExactTokensForAVAXSupportingFeeOnTransferTokens( uint amountIn, uint amountOutMin, address[] calldata path, address to, uint deadline) external;
    function quote(uint amountA, uint reserveA, uint reserveB) external pure returns (uint amountB);
    function getAmountOut(uint amountIn, uint reserveIn, uint reserveOut) external pure returns (uint amountOut);
    function getAmountIn(uint amountOut, uint reserveIn, uint reserveOut) external pure returns (uint amountIn);
    function getAmountsOut(uint amountIn, address[] memory path) external view returns (uint[] memory amounts);
    function getAmountsIn(uint amountOut, address[] memory path) external view returns (uint[] memory amounts);
}

abstract contract PefiERC20 {

    string public name = "Penguin Finance Farms";
    string public symbol = "fPEFI";
    uint8 public constant decimals = 18;
    uint256 public totalSupply;
    uint constant internal MAX_UINT = 115792089237316195423570985008687907853269984665640564039457584007913129639935;

    mapping (address => mapping (address => uint256)) internal allowances;
    mapping (address => uint256) internal balances;

    bytes32 public constant DOMAIN_TYPEHASH = 0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f;

    bytes32 public constant VERSION_HASH = 0xc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6;

    bytes32 public constant PERMIT_TYPEHASH = 0x6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9;

    mapping(address => uint) public nonces;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor() {}

    /**
     * @notice Get the number of tokens `spender` is approved to spend on behalf of `account`
     * @param account The address of the account holding the funds
     * @param spender The address of the account spending the funds
     * @return The number of tokens approved
     */
    function allowance(address account, address spender) external view returns (uint) {
        return allowances[account][spender];
    }

    /**
     * @notice Approve `spender` to transfer up to `amount` from `src`
     * @dev This will overwrite the approval amount for `spender`
     * and is subject to issues noted [here](https://eips.ethereum.org/EIPS/eip-20#approve)
     * It is recommended to use increaseAllowance and decreaseAllowance instead
     * @param spender The address of the account which may transfer tokens
     * @param amount The number of tokens that are approved (2^256-1 means infinite)
     * @return Whether or not the approval succeeded
     */
    function approve(address spender, uint256 amount) external returns (bool) {
        _approve(msg.sender, spender, amount);
        return true;
    }

    /**
     * @notice Get the number of tokens held by the `account`
     * @param account The address of the account to get the balance of
     * @return The number of tokens held
     */
    function balanceOf(address account) external view returns (uint) {
        return balances[account];
    }

    /**
     * @notice Transfer `amount` tokens from `msg.sender` to `dst`
     * @param dst The address of the destination account
     * @param amount The number of tokens to transfer
     * @return Whether or not the transfer succeeded
     */
    function transfer(address dst, uint256 amount) external returns (bool) {
        _transferTokens(msg.sender, dst, amount);
        return true;
    }

    /**
     * @notice Transfer `amount` tokens from `src` to `dst`
     * @param src The address of the source account
     * @param dst The address of the destination account
     * @param amount The number of tokens to transfer
     * @return Whether or not the transfer succeeded
     */
    function transferFrom(address src, address dst, uint256 amount) external returns (bool) {
        address spender = msg.sender;
        uint256 spenderAllowance = allowances[src][spender];

        if (spender != src && spenderAllowance != MAX_UINT) {
            uint256 newAllowance = spenderAllowance - amount;
            allowances[src][spender] = newAllowance;

            emit Approval(src, spender, newAllowance);
        }

        _transferTokens(src, dst, amount);
        return true;
    }


    /**
     * @notice Approval implementation
     * @param owner The address of the account which owns tokens
     * @param spender The address of the account which may transfer tokens
     * @param amount The number of tokens that are approved (2^256-1 means infinite)
     */
    function _approve(address owner, address spender, uint256 amount) internal {
        require(owner != address(0), "_approve::owner zero address");
        require(spender != address(0), "_approve::spender zero address");
        allowances[owner][spender] = amount;
        emit Approval(owner, spender, amount);
    }

    /**
     * @notice Transfer implementation
     * @param from The address of the account which owns tokens
     * @param to The address of the account which is receiving tokens
     * @param value The number of tokens that are being transferred
     */
    function _transferTokens(address from, address to, uint256 value) internal virtual {
        require(to != address(0), "_transferTokens: cannot transfer to the zero address");

        balances[from] -= value;
        balances[to] += value;
        emit Transfer(from, to, value);
    }

    function _mint(address to, uint256 value) internal {
        totalSupply += value;
        balances[to] += value;
        emit Transfer(address(0), to, value);
    }

    function _burn(address from, uint256 value) internal {
        balances[from] -= value;
        totalSupply -= value;
        emit Transfer(from, address(0), value);
    }

    /**
     * @notice Triggers an approval from owner to spender
     * @param owner The address to approve from
     * @param spender The address to be approved
     * @param value The number of tokens that are approved (2^256-1 means infinite)
     * @param deadline The time at which to expire the signature
     * @param v The recovery byte of the signature
     * @param r Half of the ECDSA signature pair
     * @param s Half of the ECDSA signature pair
     */
    function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
        require(deadline >= block.timestamp, "permit::expired");

        bytes32 encodeData = keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonces[owner]++, deadline));
        _validateSignedData(owner, encodeData, v, r, s);

        _approve(owner, spender, value);
    }

    /**
     * @notice Recovers address from signed data and validates the signature
     * @param signer Address that signed the data
     * @param encodeData Data signed by the address
     * @param v The recovery byte of the signature
     * @param r Half of the ECDSA signature pair
     * @param s Half of the ECDSA signature pair
     */
    function _validateSignedData(address signer, bytes32 encodeData, uint8 v, bytes32 r, bytes32 s) internal view {
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                getDomainSeparator(),
                encodeData
            )
        );
        address recoveredAddress = ecrecover(digest, v, r, s);
        // Explicitly disallow authorizations for address(0) as ecrecover returns address(0) on malformed messages
        require(recoveredAddress != address(0) && recoveredAddress == signer, "Arch::validateSig: invalid signature");
    }

    /**
     * @notice EIP-712 Domain separator
     * @return Separator
     */
    function getDomainSeparator() public view returns (bytes32) {
        return keccak256(
            abi.encode(
                DOMAIN_TYPEHASH,
                keccak256(bytes(name)),
                VERSION_HASH,
                _getChainId(),
                address(this)
            )
        );
    }

    /**
     * @notice Current id of the chain where this contract is deployed
     * @return Chain id
     */
    function _getChainId() internal view returns (uint) {
        uint256 chainId;
        assembly { chainId := chainid() }
        return chainId;
    }
}















contract PenguinStrategyGlobalVariables is Ownable {


    uint public POOL_CREATOR_FEE_BIPS;
    uint public NEST_FEE_BIPS;
    uint public DEV_FEE_BIPS;
    uint public ALTERNATE_FEE_BIPS;
    uint constant public MAX_TOTAL_FEE = 1000;

    address public devAddress;
    address public nestAddress;
    address public alternateAddress;

    event FeeStructureUpdated(uint newPOOL_CREATOR_FEE_BIPS, uint newNEST_FEE_BIPS, uint newDEV_FEE_BIPS, uint newALTERNATE_FEE_BIPS);
    event UpdateDevAddress(address oldValue, address newValue);
    event UpdateNestAddress(address oldValue, address newValue);
    event UpdateAlternateAddress(address oldValue, address newValue);

    constructor(uint newPOOL_CREATOR_FEE_BIPS, uint newNEST_FEE_BIPS, uint newDEV_FEE_BIPS, uint newALTERNATE_FEE_BIPS, address newDevAddress, address newNestAddress, address newAlternateAddress) {
        updateFeeStructure(newPOOL_CREATOR_FEE_BIPS, newNEST_FEE_BIPS, newDEV_FEE_BIPS, newALTERNATE_FEE_BIPS);
        updateDevAddress(newDevAddress);
        updateNestAddress(newNestAddress);
        updateAlternateAddress(newAlternateAddress);
    }

    function updateFeeStructure(uint newPOOL_CREATOR_FEE_BIPS, uint newNEST_FEE_BIPS, uint newDEV_FEE_BIPS, uint newALTERNATE_FEE_BIPS) public onlyOwner {
        require((newPOOL_CREATOR_FEE_BIPS + newNEST_FEE_BIPS + newDEV_FEE_BIPS + newALTERNATE_FEE_BIPS) <= MAX_TOTAL_FEE, "new fees too high");
        POOL_CREATOR_FEE_BIPS = newPOOL_CREATOR_FEE_BIPS;
        NEST_FEE_BIPS = newNEST_FEE_BIPS;
        DEV_FEE_BIPS = newDEV_FEE_BIPS;
        ALTERNATE_FEE_BIPS = newALTERNATE_FEE_BIPS;
        emit FeeStructureUpdated(newPOOL_CREATOR_FEE_BIPS, newNEST_FEE_BIPS, newDEV_FEE_BIPS, newALTERNATE_FEE_BIPS);
    }
    function updateDevAddress(address newValue) public onlyOwner {
        emit UpdateDevAddress(devAddress, newValue);
        devAddress = newValue;
    }
    function updateNestAddress(address newValue) public onlyOwner {
        emit UpdateNestAddress(nestAddress, newValue);
        nestAddress = newValue;
    }
    function updateAlternateAddress(address newValue) public onlyOwner {
        emit UpdateAlternateAddress(nestAddress, newValue);
        alternateAddress = newValue;
    }
}






/**
 * @notice PefiStrategy should be inherited by new strategies
 */
abstract contract PefiStrategy is PefiERC20, Ownable {

    uint public totalDeposits;

    IERC20 public depositToken;
    IERC20 public rewardToken;
    address public poolCreatorAddress;
    address public nestAddressLocal;
    address public devAddressLocal;
    address public alternateAddressLocal;

    uint public MIN_TOKENS_TO_REINVEST;
    uint public MAX_TOKENS_TO_DEPOSIT_WITHOUT_REINVEST;
    bool public DEPOSITS_ENABLED;

    PenguinStrategyGlobalVariables public pefiGlobalVariableContract;
    bool public USE_GLOBAL_PEFI_VARIABLES;

    uint public POOL_CREATOR_FEE_BIPS_LOCAL;
    uint public NEST_FEE_BIPS_LOCAL;
    uint public DEV_FEE_BIPS_LOCAL;
    uint public ALTERNATE_FEE_BIPS_LOCAL;

    uint constant public MAX_TOTAL_FEE = 1000;
    uint constant internal BIPS_DIVISOR = 10000;

    event Deposit(address indexed account, uint amount);
    event Withdraw(address indexed account, uint amount);
    event Reinvest(uint newTotalDeposits, uint newTotalSupply);
    event Recovered(address token, uint amount);
    event FeeStructureUpdated(uint newPOOL_CREATOR_FEE_BIPS, uint newNEST_FEE_BIPS, uint newDEV_FEE_BIPS, uint newALTERNATE_FEE_BIPS);
    event UpdateMinTokensToReinvest(uint oldValue, uint newValue);
    event UpdateMaxTokensToDepositWithoutReinvest(uint oldValue, uint newValue);
    event UpdateDevAddress(address oldValue, address newValue);
    event UpdateNestAddress(address oldValue, address newValue);
    event UpdatePoolCreatorAddress(address oldValue, address newValue);
    event UpdateAlternateAddress(address oldValue, address newValue);
    event DepositsEnabled(bool newValue);
    event UseGlobalVariablesUpdated(bool newValue);

    /**
     * @notice Throws if called by smart contract
     */
    modifier onlyEOA() {
        require(tx.origin == msg.sender, "PefiStrategy::onlyEOA");
        _;
    }

    /**
     * @notice Approve tokens for use in Strategy
     * @dev Should use modifier `onlyOwner` to avoid griefing
     */
    function setAllowances() public virtual;

    /**
     * @notice Revoke token allowance
     * @param token address
     * @param spender address
     */
    function revokeAllowance(address token, address spender) external onlyOwner {
        require(IERC20(token).approve(spender, 0));
    }

    /**
     * @notice Deposit and deploy deposits tokens to the strategy
     * @dev Must mint receipt tokens to `msg.sender`
     * @param amount deposit tokens
     */
    function deposit(uint amount) external virtual;

    /**
    * @notice Deposit using Permit
    * @dev Should revert for tokens without Permit
    * @param amount Amount of tokens to deposit
    * @param deadline The time at which to expire the signature
    * @param v The recovery byte of the signature
    * @param r Half of the ECDSA signature pair
    * @param s Half of the ECDSA signature pair
    */
    function depositWithPermit(uint amount, uint deadline, uint8 v, bytes32 r, bytes32 s) external virtual;

    /**
     * @notice Deposit on behalf of another account
     * @dev Must mint receipt tokens to `account`
     * @param account address to receive receipt tokens
     * @param amount deposit tokens
     */
    function depositFor(address account, uint amount) external virtual;

    /**
     * @notice Redeem receipt tokens for deposit tokens
     * @param amount receipt tokens
     */
    function withdraw(uint amount) external virtual;

    /**
     * @notice Reinvest reward tokens into deposit tokens
     */
    function reinvest() external virtual;

    /**
     * @notice Estimate reinvest reward
     * @return reward tokens
     */
    function estimateReinvestReward() external view returns (uint) {
        uint unclaimedRewards = checkReward();
        if (unclaimedRewards >= MIN_TOKENS_TO_REINVEST) {
            return ((unclaimedRewards * POOL_CREATOR_FEE_BIPS()) / BIPS_DIVISOR);
        }
        return 0;
    }

    /**
     * @notice Reward tokens avialable to strategy, including balance
     * @return reward tokens
     */
    function checkReward() public virtual view returns (uint);

    /**
     * @notice Aggregate all available deployed deposit tokens back to Strategy
     * @param minReturnAmountAccepted min deposit tokens to receive
     * @param disableDeposits bool
     */
    function impromptuTokenAggregation(uint minReturnAmountAccepted, bool disableDeposits) external virtual;

    /**
     * @notice Calculate receipt tokens for a given amount of deposit tokens
     * @dev If contract is empty, use 1:1 ratio
     * @dev Could return zero shares for very low amounts of deposit tokens
     * @param amount deposit tokens
     * @return receipt tokens
     */
    function getSharesForDepositTokens(uint amount) public view returns (uint) {
        if ((totalSupply * totalDeposits) == 0) {
            return amount;
        }
        return ((amount * totalSupply) / totalDeposits);
    }

    /**
     * @notice Calculate deposit tokens for a given amount of receipt tokens
     * @param amount receipt tokens
     * @return deposit tokens
     */
    function getDepositTokensForShares(uint amount) public view returns (uint) {
        if ((totalSupply * totalDeposits) == 0) {
            return 0;
        }
        return ((amount * totalDeposits) / totalSupply);
    }

    function POOL_CREATOR_FEE_BIPS() public view returns(uint) {
        if(USE_GLOBAL_PEFI_VARIABLES){
            return pefiGlobalVariableContract.POOL_CREATOR_FEE_BIPS();
        } else {
            return POOL_CREATOR_FEE_BIPS_LOCAL;
        }
    }

    function NEST_FEE_BIPS() public view returns(uint) {
        if(USE_GLOBAL_PEFI_VARIABLES){
            return pefiGlobalVariableContract.NEST_FEE_BIPS();
        } else {
            return NEST_FEE_BIPS_LOCAL;
        }
    }

    function DEV_FEE_BIPS() public view returns(uint) {
        if(USE_GLOBAL_PEFI_VARIABLES){
            return pefiGlobalVariableContract.DEV_FEE_BIPS();
        } else {
            return DEV_FEE_BIPS_LOCAL;
        }
    }

    function ALTERNATE_FEE_BIPS() public view returns(uint) {
        if(USE_GLOBAL_PEFI_VARIABLES){
            return pefiGlobalVariableContract.ALTERNATE_FEE_BIPS();
        } else {
            return ALTERNATE_FEE_BIPS_LOCAL;
        }
    }

    function devAddress() public view returns(address) {
        if(USE_GLOBAL_PEFI_VARIABLES){
            return pefiGlobalVariableContract.devAddress();
        } else {
            return devAddressLocal;
        }
    }

    function nestAddress() public view returns(address) {
        if(USE_GLOBAL_PEFI_VARIABLES){
            return pefiGlobalVariableContract.nestAddress();
        } else {
            return nestAddressLocal;
        }
    }

    function alternateAddress() public view returns(address) {
        if(USE_GLOBAL_PEFI_VARIABLES){
            return pefiGlobalVariableContract.alternateAddress();
        } else {
            return alternateAddressLocal;
        }
    }

    function updateUseGlobalVariables(bool newValue) external onlyOwner {
        USE_GLOBAL_PEFI_VARIABLES = newValue;
        emit UseGlobalVariablesUpdated(newValue);
    }

    /**
     * @notice Update reinvest min threshold
     * @param newValue threshold
     */
    function updateMinTokensToReinvest(uint newValue) public onlyOwner {
        emit UpdateMinTokensToReinvest(MIN_TOKENS_TO_REINVEST, newValue);
        MIN_TOKENS_TO_REINVEST = newValue;
    }

    /**
     * @notice Update reinvest max threshold before a deposit
     * @param newValue threshold
     */
    function updateMaxTokensToDepositWithoutReinvest(uint newValue) public onlyOwner {
        emit UpdateMaxTokensToDepositWithoutReinvest(MAX_TOKENS_TO_DEPOSIT_WITHOUT_REINVEST, newValue);
        MAX_TOKENS_TO_DEPOSIT_WITHOUT_REINVEST = newValue;
    }

    function updateFeeStructure(uint newPOOL_CREATOR_FEE_BIPS, uint newNEST_FEE_BIPS, uint newDEV_FEE_BIPS, uint newALTERNATE_FEE_BIPS) public onlyOwner {
        require((newPOOL_CREATOR_FEE_BIPS + newNEST_FEE_BIPS + newDEV_FEE_BIPS + newALTERNATE_FEE_BIPS) <= MAX_TOTAL_FEE, "new fees too high");
        POOL_CREATOR_FEE_BIPS_LOCAL = newPOOL_CREATOR_FEE_BIPS;
        NEST_FEE_BIPS_LOCAL = newNEST_FEE_BIPS;
        DEV_FEE_BIPS_LOCAL = newDEV_FEE_BIPS;
        ALTERNATE_FEE_BIPS_LOCAL = newALTERNATE_FEE_BIPS;
        emit FeeStructureUpdated(newPOOL_CREATOR_FEE_BIPS, newNEST_FEE_BIPS, newDEV_FEE_BIPS, newALTERNATE_FEE_BIPS);
    }

    /**
     * @notice Enable/disable deposits
     * @param newValue bool
     */
    function updateDepositsEnabled(bool newValue) public onlyOwner {
        require(DEPOSITS_ENABLED != newValue);
        DEPOSITS_ENABLED = newValue;
        emit DepositsEnabled(newValue);
    }

    /**
     * @notice Update poolCreatorAddress
     * @param newValue address
     */
    function updatePoolCreatorAddress(address newValue) public onlyOwner {
        emit UpdatePoolCreatorAddress(poolCreatorAddress, newValue);
        poolCreatorAddress = newValue;
    }

    /**
     * @notice Update nestAddressLocal
     * @param newValue address
     */
    function updateNestAddress(address newValue) public onlyOwner {
        emit UpdateNestAddress(nestAddressLocal, newValue);
        nestAddressLocal = newValue;
    }

    /**
     * @notice Update devAddressLocal
     * @param newValue address
     */
    function updateDevAddress(address newValue) public onlyOwner {
        emit UpdateDevAddress(devAddressLocal, newValue);
        devAddressLocal = newValue;
    }

    /**
     * @notice Update alternateAddressLocal
     * @param newValue address
     */
    function updateAlternateAddress(address newValue) public onlyOwner {
        emit UpdateAlternateAddress(alternateAddressLocal, newValue);
        alternateAddressLocal = newValue;
    }

    /**
     * @notice Recover ERC20 tokens accidentally sent to contract
     * @param tokenAddress token address
     * @param tokenAmount amount to recover
     */
    function recoverERC20(address tokenAddress, uint tokenAmount) external virtual onlyOwner {
        require(tokenAmount > 0, "cannot recover 0 tokens");
        require(tokenAddress != address(depositToken), "PefiStrategy:: cannot recover deposit token");
        require(IERC20(tokenAddress).transfer(msg.sender, tokenAmount), "PefiStrategy:: token recovery failed");
        emit Recovered(tokenAddress, tokenAmount);
    }

    /**
     * @notice Recover AVAX from contract
     * @param amount amount
     */
    function recoverAVAX(uint amount) external onlyOwner {
        require(amount > 0);
        payable(msg.sender).transfer(amount);
        emit Recovered(address(0), amount);
    }
}













interface IMasterChef {
    function poolLength() external view returns (uint256);
    function add(uint256 _allocPoint, address _lpToken, uint16 _withdrawFeeBP, bool _withUpdate) external;
    function set(uint256 _pid, uint256 _allocPoint, uint16 _withdrawFeeBP, bool _withUpdate) external;
    function setMigrator(address _migrator) external;
    function migrate(uint256 _pid) external;
    function getMultiplier(uint256 _from, uint256 _to) external view returns (uint256);
    function massUpdatePools() external;
    function updatePool(uint256 _pid) external;
    function deposit(uint256 _pid, uint256 _amount) external;
    function withdraw(uint256 _pid, uint256 _amount) external;
    function emergencyWithdraw(uint256 _pid) external;
    function dev(address _devaddr) external;
    function userInfo(uint pid, address user) external view returns (
        uint256 amount,
        uint256 rewardDebt
    );
    event Deposit(address indexed user, uint256 indexed pid, uint256 amount);
    event Withdraw(address indexed user, uint256 indexed pid, uint256 amount);
    event EmergencyWithdraw(address indexed user, uint256 indexed pid, uint256 amount);
}




abstract contract PefiStrategyForLP is PefiStrategy {

    IRouter public router;
    address public stakingContract;
    address public token0;
    address public token1;
    address[] pathRewardToToken0;
    address[] pathRewardToToken1;
    uint public PID;

    constructor(
        string memory _name,
        address[8] memory _initAddressArray, //depositToken, rewardToken, stakingContract, router, poolCreator, nest, dev, alternate
        uint _pid,
        uint _minTokensToReinvest,
        uint[4] memory _initFeeStructure, //pool creator, nest, dev, alternate
        address[] memory _pathRewardToToken0,
        address[] memory _pathRewardToToken1,
        address _pefiGlobalVariables,
        bool _USE_GLOBAL_PEFI_VARIABLES
    ) {
        name = _name;
        depositToken = IPair(_initAddressArray[0]);
        rewardToken = IERC20(_initAddressArray[1]);
        stakingContract = _initAddressArray[2];
        router = IRouter(_initAddressArray[3]);
        updatePoolCreatorAddress(_initAddressArray[4]);
        updateNestAddress(_initAddressArray[5]);
        updateDevAddress(_initAddressArray[6]);
        updateAlternateAddress(_initAddressArray[7]);
        PID = _pid;
        pathRewardToToken0 = _pathRewardToToken0;
        pathRewardToToken1 = _pathRewardToToken1;
        token0 = _pathRewardToToken0[_pathRewardToToken0.length - 1];
        token1 = _pathRewardToToken1[_pathRewardToToken1.length - 1];
        pefiGlobalVariableContract = PenguinStrategyGlobalVariables(_pefiGlobalVariables);
        USE_GLOBAL_PEFI_VARIABLES = _USE_GLOBAL_PEFI_VARIABLES;
        setAllowances();
        updateMinTokensToReinvest(_minTokensToReinvest);
        updateFeeStructure(_initFeeStructure[0], _initFeeStructure[1], _initFeeStructure[2], _initFeeStructure[3]);
        updateDepositsEnabled(true);

        emit Reinvest(0, 0);
    }


    /**
    * @notice Approve tokens for use in Strategy
    * @dev Restricted to avoid griefing attacks
    */
    function setAllowances() public override onlyOwner {
        depositToken.approve(address(stakingContract), MAX_UINT);
        rewardToken.approve(address(router), MAX_UINT);
        IERC20(IPair(address(depositToken)).token0()).approve(address(router), MAX_UINT);
        IERC20(IPair(address(depositToken)).token1()).approve(address(router), MAX_UINT);
    }

    /**
    * @notice Deposit tokens to receive receipt tokens
    * @param amount Amount of tokens to deposit
    */
    function deposit(uint amount) external virtual override {
        _deposit(msg.sender, amount);
    }

    /**
    * @notice Deposit using Permit
    * @param amount Amount of tokens to deposit
    * @param deadline The time at which to expire the signature
    * @param v The recovery byte of the signature
    * @param r Half of the ECDSA signature pair
    * @param s Half of the ECDSA signature pair
    */
    function depositWithPermit(uint amount, uint deadline, uint8 v, bytes32 r, bytes32 s) external override {
        depositToken.permit(msg.sender, address(this), amount, deadline, v, r, s);
        _deposit(msg.sender, amount);
    }

    function depositFor(address account, uint amount) external override {
        _deposit(account, amount);
    }

    function _deposit(address account, uint amount) internal virtual {
    require(DEPOSITS_ENABLED == true, "PefiStrategyForLP::_deposit");
        if (MAX_TOKENS_TO_DEPOSIT_WITHOUT_REINVEST > 0) {
            uint unclaimedRewards = checkReward();
        if (unclaimedRewards > MAX_TOKENS_TO_DEPOSIT_WITHOUT_REINVEST) {
            _reinvest(unclaimedRewards);
        }
    }
        require(depositToken.transferFrom(msg.sender, address(this), amount));
        _stakeDepositTokens(amount);
        _mint(account, getSharesForDepositTokens(amount));
        totalDeposits += amount;
        emit Deposit(account, amount);
    }

    function _withdrawDepositTokens(uint amount) internal {
        require(amount > 0, "PefiStrategyForLP::_withdrawDepositTokens");
        IMasterChef(stakingContract).withdraw(PID, amount);
    }

    function reinvest() external override onlyEOA {
        uint unclaimedRewards = checkReward();
        require(unclaimedRewards >= MIN_TOKENS_TO_REINVEST, "PefiStrategyForLP::reinvest");
        _reinvest(unclaimedRewards);
    }

    function withdraw(uint amount) external virtual override {
        uint depositTokenAmount = getDepositTokensForShares(amount);
        if (depositTokenAmount > 0) {
            _withdrawDepositTokens(depositTokenAmount);
            require(depositToken.transfer(msg.sender, depositTokenAmount), "transfer failed");
            _burn(msg.sender, amount);
            totalDeposits -= depositTokenAmount;
            emit Withdraw(msg.sender, depositTokenAmount);
        }
    }

    /**
    * @notice Reinvest rewards from staking contract to deposit tokens
    * @dev Reverts if the expected amount of tokens are not returned from `stakingContract`
    * @param amount deposit tokens to reinvest
    */
    function _reinvest(uint amount) internal virtual {
        IMasterChef(stakingContract).deposit(PID, 0);

        uint devFee = (amount * DEV_FEE_BIPS()) / BIPS_DIVISOR;
        if (devFee > 0) {
            require(rewardToken.transfer(devAddress(), devFee), "PefiStrategyForLP::_reinvest, dev");
        }

        uint nestFee = (amount * NEST_FEE_BIPS()) / BIPS_DIVISOR;
        if (nestFee > 0) {
            require(rewardToken.transfer(nestAddress(), nestFee), "PefiStrategyForLP::_reinvest, nest");
        }

        uint poolCreatorFee = (amount * POOL_CREATOR_FEE_BIPS()) / BIPS_DIVISOR;
        if (poolCreatorFee > 0) {
            require(rewardToken.transfer(poolCreatorAddress, poolCreatorFee), "PefiStrategyForLP::_reinvest, poolCreator");
        }

        uint alternateFee = (amount * ALTERNATE_FEE_BIPS()) / BIPS_DIVISOR;
        if (alternateFee > 0) {
            require(rewardToken.transfer(alternateAddress(), alternateFee), "PefiStrategyForLP::_reinvest, alternate");
        }

        uint depositTokenAmount = _convertRewardTokensToDepositTokens(
            (amount - (devFee + nestFee + poolCreatorFee + alternateFee))
        );

        _stakeDepositTokens(depositTokenAmount);
        totalDeposits += depositTokenAmount;

        emit Reinvest(totalDeposits, totalSupply);
    }

    function _stakeDepositTokens(uint amount) internal {
        require(amount > 0, "PefiStrategyForLP::_stakeDepositTokens");
        IMasterChef(stakingContract).deposit(PID, amount);
    }

    /**
    * @notice Converts reward tokens to deposit tokens
    * @dev Always converts through router; there are no price checks enabled
    * @return deposit tokens received
    */
    function _convertRewardTokensToDepositTokens(uint amount) internal returns (uint) {
        uint amountIn = (amount / 2);
        require(amountIn > 0, "PefiStrategyForLP::_convertRewardTokensToDepositTokens");

        // swap to token0
        uint amountOutToken0 = amountIn;
        if (pathRewardToToken0.length != 1) {
            uint[] memory amountsOutToken0 = router.getAmountsOut(amountIn, pathRewardToToken0);
            amountOutToken0 = amountsOutToken0[amountsOutToken0.length - 1];
            router.swapExactTokensForTokens(amountIn, amountOutToken0, pathRewardToToken0, address(this), block.timestamp);
        }

        // swap to token1
        uint amountOutToken1 = amountIn;
        if (pathRewardToToken1.length != 1) {
            uint[] memory amountsOutToken1 = router.getAmountsOut(amountIn, pathRewardToToken1);
            amountOutToken1 = amountsOutToken1[amountsOutToken1.length - 1];
            router.swapExactTokensForTokens(amountIn, amountOutToken1, pathRewardToToken1, address(this), block.timestamp);
        }

        (,,uint liquidity) = router.addLiquidity(
            token0, token1,
            amountOutToken0, amountOutToken1,
            0, 0,
            address(this),
            block.timestamp
        );

        return liquidity;
    }

    function impromptuTokenAggregation(uint minReturnAmountAccepted, bool disableDeposits) external override onlyOwner {
        uint balanceBefore = depositToken.balanceOf(address(this));
        IMasterChef(stakingContract).emergencyWithdraw(PID);
        uint balanceAfter = depositToken.balanceOf(address(this));
        require(balanceAfter - balanceBefore >= minReturnAmountAccepted, "PefiStrategyForLP::impromptuTokenAggregation");
        totalDeposits = balanceAfter;
        emit Reinvest(totalDeposits, totalSupply);
        if (DEPOSITS_ENABLED == true && disableDeposits == true) {
        updateDepositsEnabled(false);
        }
    }

}







interface XPEFI is IERC20 {
    function enter(uint256 _amount) external;
    function leave(uint256 _share) external;
}

interface IPenguinChef is IMasterChef {
    function pefi() external view returns (address);
    function pefiPerBlock() external view returns (uint256);
    function pendingPEFI(uint256 _pid, address _user) external view returns (uint256);
    function poolInfo(uint pid) external view returns (
        address lpToken,
        uint allocPoint,
        uint lastRewardBlock,
        uint accPEFIPerShare,
        uint16 withdrawFeeBP
    );
}

/**
 * @notice strategy for Penguin Igloos
 */
contract PenguinStrategyForIgloos is PefiStrategyForLP {

    uint public xPefiPerShare; //stores cumulative xPEFI per share, scaled up by 1e18
    uint public NEST_STAKING_BIPS; //share of rewards sent to the nest on behalf of users
    mapping(address=>uint) public xPefiDebt; //pending xPEFI for any address is (its balance * xPefiPerShare) - (its xPefiDebt)

    event StakedPEFI(uint amountPefiSentToNest);
    event ClaimedxPEFI(address indexed account, uint amount);
    event NestStakingBipsChanged(uint oldNEST_STAKING_BIPS, uint newNEST_STAKING_BIPS);


    constructor(
        string memory _name,
        address[8] memory _initAddressArray, //depositToken, rewardToken, stakingContract, router, poolCreator, nest, dev, alternate
        uint _pid,
        uint _minTokensToReinvest,
        uint[4] memory _initFeeStructure, //pool creator, nest, dev, alternate
        address[] memory _pathRewardToToken0,
        address[] memory _pathRewardToToken1,
        address _pefiGlobalVariables,
        bool _USE_GLOBAL_PEFI_VARIABLES
    )
    PefiStrategyForLP(
        _name,
        _initAddressArray,
        _pid,
        _minTokensToReinvest,
        _initFeeStructure,
        _pathRewardToToken0,
        _pathRewardToToken1,
        _pefiGlobalVariables,
        _USE_GLOBAL_PEFI_VARIABLES
    )
    {}

    function withdraw(uint amount) external override {
        claimXPEFI();
        uint depositTokenAmount = getDepositTokensForShares(amount);
        if (depositTokenAmount > 0) {
            _withdrawDepositTokens(depositTokenAmount);
            (,,,, uint withdrawFeeBP) = IPenguinChef(stakingContract).poolInfo(PID);
            uint withdrawFee = ((depositTokenAmount * withdrawFeeBP) / BIPS_DIVISOR);
            require(depositToken.transfer(msg.sender, (depositTokenAmount - withdrawFee)), "PenguinStrategyForIgloos::withdraw");
            _burn(msg.sender, amount);
            totalDeposits -= depositTokenAmount;
            emit Withdraw(msg.sender, depositTokenAmount);
        }
        xPefiDebt[msg.sender] = (xPefiPerShare * balances[msg.sender]);
    }

    function checkReward() public override view returns (uint) {
        uint pendingReward = IPenguinChef(stakingContract).pendingPEFI(PID, address(this));
        uint contractBalance = rewardToken.balanceOf(address(this));
        return (pendingReward + contractBalance);
    }

    /**
    * @notice Estimate recoverable balance after withdraw fee
    * @return deposit tokens after withdraw fee
    */
    function estimateDeployedBalance() external view returns (uint) {
        (uint depositBalance, ) = IMasterChef(stakingContract).userInfo(PID, address(this));
        (,,,, uint withdrawFeeBP) = IPenguinChef(stakingContract).poolInfo(PID);
        uint withdrawFee = ((depositBalance * withdrawFeeBP) / BIPS_DIVISOR);
        return (depositBalance - withdrawFee);
    }

    function pendingXPefi(address user) public view returns(uint) {
        return((xPefiPerShare * balances[user] - xPefiDebt[user]) / 1e18);
    }

    function claimXPEFI() public {
        _claimXPEFIInternal(msg.sender);
    }

    function updateNestStakingBips(uint newNEST_STAKING_BIPS) public onlyOwner {
        require(newNEST_STAKING_BIPS <= BIPS_DIVISOR, "PenguinStrategyForIgloos::setNEST_STAKING_BIPS");
        emit NestStakingBipsChanged(NEST_STAKING_BIPS, newNEST_STAKING_BIPS);
        NEST_STAKING_BIPS = newNEST_STAKING_BIPS;
    }

    /**
    * @notice Reinvest rewards from staking contract to deposit tokens
    * @dev Reverts if the expected amount of tokens are not returned from `stakingContract`
    * @param amount deposit tokens to reinvest
    */
    function _reinvest(uint amount) internal override {
        IMasterChef(stakingContract).deposit(PID, 0);

        uint devFee = (amount * DEV_FEE_BIPS()) / BIPS_DIVISOR;
        if (devFee > 0) {
            require(rewardToken.transfer(devAddress(), devFee), "PenguinStrategyForIgloos::_reinvest, dev");
        }

        uint nestFee = (amount * NEST_FEE_BIPS()) / BIPS_DIVISOR;
        if (nestFee > 0) {
            require(rewardToken.transfer(nestAddress(), nestFee), "PenguinStrategyForIgloos::_reinvest, nest");
        }

        uint poolCreatorFee = (amount * POOL_CREATOR_FEE_BIPS()) / BIPS_DIVISOR;
        if (poolCreatorFee > 0) {
            require(rewardToken.transfer(poolCreatorAddress, poolCreatorFee), "PenguinStrategyForIgloos::_reinvest, poolCreator");
        }

        uint alternateFee = (amount * ALTERNATE_FEE_BIPS()) / BIPS_DIVISOR;
        if (alternateFee > 0) {
            require(rewardToken.transfer(alternateAddress(), alternateFee), "PenguinStrategyForIgloos::_reinvest, alternate");
        }

        uint remainingAmount = (amount - (devFee + nestFee + poolCreatorFee + alternateFee));
        uint toNest = remainingAmount * NEST_STAKING_BIPS / BIPS_DIVISOR;
        uint toDepositTokens = remainingAmount - toNest;

        if (toNest > 0) {
            _depositToNest(toNest);
        }

        if (toDepositTokens > 0) {
            uint depositTokenAmount = _convertRewardTokensToDepositTokens(toDepositTokens);
            _stakeDepositTokens(depositTokenAmount);
            totalDeposits += depositTokenAmount;
        }

        emit Reinvest(totalDeposits, totalSupply);
    }

    //deposits amount of PEFI to the nest and accounts for it
    function _depositToNest(uint amountPEFI) internal {
        uint xPefiBefore = XPEFI(nestAddress()).balanceOf(address(this));
        rewardToken.approve(nestAddress(), amountPEFI);
        XPEFI(nestAddress()).enter(amountPEFI);
        uint xPefiAfter = XPEFI(nestAddress()).balanceOf(address(this));
        _updateXPefiPerShare(xPefiAfter - xPefiBefore);
        emit StakedPEFI(amountPEFI);
    }

    //updates the value of xPefiPerShare whenever PEFI is sent to the nest
    function _updateXPefiPerShare(uint newXPefi) internal {
        if (totalSupply > 0) {
            xPefiPerShare += ((newXPefi * 1e18) / totalSupply);
        }
    }

    function _claimXPEFIInternal(address user) internal {
        uint amountPending = pendingXPefi(user);
        if (amountPending > 0) {
            xPefiDebt[user] = (xPefiPerShare * balances[user]);
            XPEFI(nestAddress()).transfer(user, amountPending);
            emit ClaimedxPEFI(user, amountPending);
        }
    }

    function _transferTokens(address from, address to, uint256 value) internal override {
        require(to != address(0), "_transferTokens: cannot transfer to the zero address");
        _claimXPEFIInternal(from);
        _claimXPEFIInternal(to);
        balances[from] -= value;
        balances[to] += value;
        xPefiDebt[from] = (xPefiPerShare * balances[from]);
        xPefiDebt[to] = (xPefiPerShare * balances[to]);
        emit Transfer(from, to, value);
    }

    function _deposit(address account, uint amount) internal override {
        require(DEPOSITS_ENABLED == true, "PenguinStrategyForIgloos::_deposit");
        _claimXPEFIInternal(account);
        if (MAX_TOKENS_TO_DEPOSIT_WITHOUT_REINVEST > 0) {
            uint unclaimedRewards = checkReward();
            if (unclaimedRewards > MAX_TOKENS_TO_DEPOSIT_WITHOUT_REINVEST) {
                _reinvest(unclaimedRewards);
            }
        }
        require(depositToken.transferFrom(msg.sender, address(this), amount));
        _stakeDepositTokens(amount);
        _mint(account, getSharesForDepositTokens(amount));
        totalDeposits += amount;
        xPefiDebt[account] = (xPefiPerShare * balances[account]);
        emit Deposit(account, amount);
    }
}










interface IOliveChef is IMasterChef {
    function olive() external view returns (address);
    function olivePerBlock() external view returns (uint256);
    function pendingOlive(uint256 _pid, address _user) external view returns (uint256);
    function poolInfo(uint pid) external view returns (
        address lpToken,
        uint allocPoint,
        uint lastRewardBlock,
        uint accOlivePerShare
    );
}

/**
 * @notice strategy for Olive
 */
contract PenguinStrategyForOliveLPs is PefiStrategyForLP {

    constructor(
        string memory _name,
        address[8] memory _initAddressArray, //depositToken, rewardToken, stakingContract, router, poolCreator, nest, dev, alternate
        uint _pid,
        uint _minTokensToReinvest,
        uint[4] memory _initFeeStructure, //pool creator, nest, dev, alternate
        address[] memory _pathRewardToToken0,
        address[] memory _pathRewardToToken1,
        address _pefiGlobalVariables,
        bool _USE_GLOBAL_PEFI_VARIABLES
    )
    PefiStrategyForLP(
        _name,
        _initAddressArray,
        _pid,
        _minTokensToReinvest,
        _initFeeStructure,
        _pathRewardToToken0,
        _pathRewardToToken1,
        _pefiGlobalVariables,
        _USE_GLOBAL_PEFI_VARIABLES
    )
    {}

    function checkReward() public view override returns (uint) {
        uint pendingReward = IOliveChef(stakingContract).pendingOlive(PID, address(this));
        uint contractBalance = rewardToken.balanceOf(address(this));
        return (pendingReward + contractBalance);
    }
}









interface IBambooChef is IMasterChef {
    function bamboo() external view returns (address);
    function bambooPerBlock() external view returns (uint256);
    function pendingBamboo(uint256 _pid, address _user) external view returns (uint256);
    function poolInfo(uint pid) external view returns (
        address lpToken,
        uint allocPoint,
        uint lastRewardBlock,
        uint accSushiPerShare
    );
}

/**
 * @notice strategy for Bamboo
 */
contract PenguinStrategyForBambooLPs is PefiStrategyForLP {

    constructor(
        string memory _name,
        address[8] memory _initAddressArray, //depositToken, rewardToken, stakingContract, router, poolCreator, nest, dev, alternate
        uint _pid,
        uint _minTokensToReinvest,
        uint[4] memory _initFeeStructure, //pool creator, nest, dev, alternate
        address[] memory _pathRewardToToken0,
        address[] memory _pathRewardToToken1,
        address _pefiGlobalVariables,
        bool _USE_GLOBAL_PEFI_VARIABLES
    )
    PefiStrategyForLP(
        _name,
        _initAddressArray,
        _pid,
        _minTokensToReinvest,
        _initFeeStructure,
        _pathRewardToToken0,
        _pathRewardToToken1,
        _pefiGlobalVariables,
        _USE_GLOBAL_PEFI_VARIABLES
    )
    {}

    /**
    * @notice Reward token balance that can be reinvested
    * @dev Staking rewards accurue to contract on each deposit/withdrawal
    * @return Unclaimed rewards, plus contract balance
    */
    function checkReward() public view override returns (uint) {
        uint pendingReward = IBambooChef(stakingContract).pendingBamboo(PID, address(this));
        uint contractBalance = rewardToken.balanceOf(address(this));
        return (pendingReward + contractBalance);
    }
}










interface IGondolaChef is IMasterChef {
    function gondola() external view returns (address);
    function gondolaPerSec() external view returns (uint256);
    function pendingGondola(uint256 _pid, address _user) external view returns (uint256);
    function poolInfo(uint pid) external view returns (
        address lpToken,
        uint allocPoint,
        uint lastRewardAt,
        uint accGondolaPerShare
    );
}

/**
 * @notice strategy for Gondola
 */
contract PenguinStrategyForGondolaLPs is PefiStrategyForLP {

    constructor(
        string memory _name,
        address[8] memory _initAddressArray, //depositToken, rewardToken, stakingContract, router, poolCreator, nest, dev, alternate
        uint _pid,
        uint _minTokensToReinvest,
        uint[4] memory _initFeeStructure, //pool creator, nest, dev, alternate
        address[] memory _pathRewardToToken0,
        address[] memory _pathRewardToToken1,
        address _pefiGlobalVariables,
        bool _USE_GLOBAL_PEFI_VARIABLES
    )
    PefiStrategyForLP(
        _name,
        _initAddressArray,
        _pid,
        _minTokensToReinvest,
        _initFeeStructure,
        _pathRewardToToken0,
        _pathRewardToToken1,
        _pefiGlobalVariables,
        _USE_GLOBAL_PEFI_VARIABLES
    )
    {}

    /**
    * @notice Reward token balance that can be reinvested
    * @dev Staking rewards accurue to contract on each deposit/withdrawal
    * @return Unclaimed rewards, plus contract balance
    */
    function checkReward() public view override returns (uint) {
        uint pendingReward = IGondolaChef(stakingContract).pendingGondola(PID, address(this));
        uint contractBalance = rewardToken.balanceOf(address(this));
        return (pendingReward + contractBalance);
    }
}









interface ILydiaChef is IMasterChef {
    function lyd() external view returns (address);
    function electrum() external view returns (address);
    function lydPerSec() external view returns (uint256);
    function pendingLyd(uint256 _pid, address _user) external view returns (uint256);
    function poolInfo(uint pid) external view returns (
        address lpToken,
        uint allocPoint,
        uint lastRewardTimestamp,
        uint accLydPerShare
    );
}

/**
 * @notice strategy for Lydia
 */
contract PenguinStrategyForLydiaLPs is PefiStrategyForLP {

    constructor(
        string memory _name,
        address[8] memory _initAddressArray, //depositToken, rewardToken, stakingContract, router, poolCreator, nest, dev, alternate
        uint _pid,
        uint _minTokensToReinvest,
        uint[4] memory _initFeeStructure, //pool creator, nest, dev, alternate
        address[] memory _pathRewardToToken0,
        address[] memory _pathRewardToToken1,
        address _pefiGlobalVariables,
        bool _USE_GLOBAL_PEFI_VARIABLES
    )
    PefiStrategyForLP(
        _name,
        _initAddressArray,
        _pid,
        _minTokensToReinvest,
        _initFeeStructure,
        _pathRewardToToken0,
        _pathRewardToToken1,
        _pefiGlobalVariables,
        _USE_GLOBAL_PEFI_VARIABLES
    )
    {}

    /**
    * @notice Reward token balance that can be reinvested
    * @dev Staking rewards accurue to contract on each deposit/withdrawal
    * @return Unclaimed rewards, plus contract balance
    */
    function checkReward() public view override returns (uint) {
        uint pendingReward = ILydiaChef(stakingContract).pendingLyd(PID, address(this));
        uint contractBalance = rewardToken.balanceOf(address(this));
        return (pendingReward + contractBalance);
    }
}










interface IStakingRewards {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function lastTimeRewardApplicable() external view returns (uint256);
    function rewardPerToken() external view returns (uint256);
    function earned(address account) external view returns (uint256);
    function getRewardForDuration() external view returns (uint256);
    function stake(uint256 amount) external;
    function stakeWithPermit(uint256 amount, uint deadline, uint8 v, bytes32 r, bytes32 s) external;
    function withdraw(uint256 amount) external;
    function getReward() external;
    function exit() external;
    event RewardAdded(uint256 reward);
    event Staked(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);
    event RewardPaid(address indexed user, uint256 reward);
    event RewardsDurationUpdated(uint256 newDuration);
    event Recovered(address token, uint256 amount);
}


/**
 * @notice strategy for Pangolin
 */
contract PenguinStrategyForPangolinLPs is PefiStrategy {

    IRouter public router;
    address public stakingContract;
    address public token0;
    address public token1;
    address[] pathRewardToToken0;
    address[] pathRewardToToken1;

    constructor(
        string memory _name,
        address[8] memory _initAddressArray, //depositToken, rewardToken, stakingContract, router, poolCreator, nest, dev, alternate
        uint _minTokensToReinvest,
        uint[4] memory _initFeeStructure, //pool creator, nest, dev, alternate
        address[] memory _pathRewardToToken0,
        address[] memory _pathRewardToToken1,
        address _pefiGlobalVariables,
        bool _USE_GLOBAL_PEFI_VARIABLES
    ) {
        name = _name;
        depositToken = IPair(_initAddressArray[0]);
        rewardToken = IERC20(_initAddressArray[1]);
        stakingContract = _initAddressArray[2];
        router = IRouter(_initAddressArray[3]);
        updatePoolCreatorAddress(_initAddressArray[4]);
        updateNestAddress(_initAddressArray[5]);
        updateDevAddress(_initAddressArray[6]);
        updateAlternateAddress(_initAddressArray[7]);
        pathRewardToToken0 = _pathRewardToToken0;
        pathRewardToToken1 = _pathRewardToToken1;
        token0 = _pathRewardToToken0[_pathRewardToToken0.length - 1];
        token1 = _pathRewardToToken1[_pathRewardToToken1.length - 1];
        pefiGlobalVariableContract = PenguinStrategyGlobalVariables(_pefiGlobalVariables);
        USE_GLOBAL_PEFI_VARIABLES = _USE_GLOBAL_PEFI_VARIABLES;
        setAllowances();
        updateMinTokensToReinvest(_minTokensToReinvest);
        updateFeeStructure(_initFeeStructure[0], _initFeeStructure[1], _initFeeStructure[2], _initFeeStructure[3]);
        updateDepositsEnabled(true);

        emit Reinvest(0, 0);
    }


    /**
    * @notice Approve tokens for use in Strategy
    * @dev Restricted to avoid griefing attacks
    */
    function setAllowances() public override onlyOwner {
        depositToken.approve(address(stakingContract), MAX_UINT);
        rewardToken.approve(address(router), MAX_UINT);
        IERC20(IPair(address(depositToken)).token0()).approve(address(router), MAX_UINT);
        IERC20(IPair(address(depositToken)).token1()).approve(address(router), MAX_UINT);
    }

    /**
    * @notice Deposit tokens to receive receipt tokens
    * @param amount Amount of tokens to deposit
    */
    function deposit(uint amount) external override {
        _deposit(msg.sender, amount);
    }

    /**
    * @notice Deposit using Permit
    * @param amount Amount of tokens to deposit
    * @param deadline The time at which to expire the signature
    * @param v The recovery byte of the signature
    * @param r Half of the ECDSA signature pair
    * @param s Half of the ECDSA signature pair
    */
    function depositWithPermit(uint amount, uint deadline, uint8 v, bytes32 r, bytes32 s) external override {
        depositToken.permit(msg.sender, address(this), amount, deadline, v, r, s);
        _deposit(msg.sender, amount);
    }

    function depositFor(address account, uint amount) external override {
        _deposit(account, amount);
    }

    function _deposit(address account, uint amount) internal {
        require(DEPOSITS_ENABLED == true, "PenguinStrategyForPangolin::_deposit");
        if (MAX_TOKENS_TO_DEPOSIT_WITHOUT_REINVEST > 0) {
            uint unclaimedRewards = checkReward();
            if (unclaimedRewards > MAX_TOKENS_TO_DEPOSIT_WITHOUT_REINVEST) {
                _reinvest(unclaimedRewards);
            }
        }
        require(depositToken.transferFrom(msg.sender, address(this), amount));
        _stakeDepositTokens(amount);
        _mint(account, getSharesForDepositTokens(amount));
        totalDeposits += amount;
        emit Deposit(account, amount);
    }

    function _withdrawDepositTokens(uint amount) internal {
        require(amount > 0, "PenguinStrategyForPangolin::_withdrawDepositTokens");
        IStakingRewards(stakingContract).withdraw(amount);
    }

    function reinvest() external override onlyEOA {
        uint unclaimedRewards = checkReward();
        require(unclaimedRewards >= MIN_TOKENS_TO_REINVEST, "PenguinStrategyForPangolin::reinvest");
        _reinvest(unclaimedRewards);
    }

    function withdraw(uint amount) external virtual override {
        uint depositTokenAmount = getDepositTokensForShares(amount);
        if (depositTokenAmount > 0) {
            _withdrawDepositTokens(depositTokenAmount);
            require(depositToken.transfer(msg.sender, depositTokenAmount), "transfer failed");
            _burn(msg.sender, amount);
            totalDeposits -= depositTokenAmount;
            emit Withdraw(msg.sender, depositTokenAmount);
        }
    }

    /**
    * @notice Reinvest rewards from staking contract to deposit tokens
    * @dev Reverts if the expected amount of tokens are not returned from `stakingContract`
    * @param amount deposit tokens to reinvest
    */
    function _reinvest(uint amount) internal {
        IStakingRewards(stakingContract).getReward();

        uint devFee = (amount * DEV_FEE_BIPS()) / BIPS_DIVISOR;
        if (devFee > 0) {
            require(rewardToken.transfer(devAddress(), devFee), "PenguinStrategyForPangolin::_reinvest, dev");
        }

        uint nestFee = (amount * NEST_FEE_BIPS()) / BIPS_DIVISOR;
        if (nestFee > 0) {
            require(rewardToken.transfer(nestAddress(), nestFee), "PenguinStrategyForPangolin::_reinvest, nest");
        }

        uint poolCreatorFee = (amount * POOL_CREATOR_FEE_BIPS()) / BIPS_DIVISOR;
        if (poolCreatorFee > 0) {
            require(rewardToken.transfer(poolCreatorAddress, poolCreatorFee), "PenguinStrategyForPangolin::_reinvest, poolCreator");
        }

        uint alternateFee = (amount * ALTERNATE_FEE_BIPS()) / BIPS_DIVISOR;
        if (alternateFee > 0) {
            require(rewardToken.transfer(alternateAddress(), alternateFee), "PenguinStrategyForPangolin::_reinvest, alternate");
        }

        uint depositTokenAmount = _convertRewardTokensToDepositTokens(
            (amount - (devFee + nestFee + poolCreatorFee + alternateFee))
        );

        _stakeDepositTokens(depositTokenAmount);
        totalDeposits += depositTokenAmount;

        emit Reinvest(totalDeposits, totalSupply);
    }

    function _stakeDepositTokens(uint amount) internal {
        require(amount > 0, "PenguinStrategyForPangolin::_stakeDepositTokens");
        IStakingRewards(stakingContract).stake(amount);
    }

    /**
    * @notice Converts reward tokens to deposit tokens
    * @dev Always converts through router; there are no price checks enabled
    * @return deposit tokens received
    */
    function _convertRewardTokensToDepositTokens(uint amount) internal returns (uint) {
        uint amountIn = (amount / 2);
        require(amountIn > 0, "PenguinStrategyForPangolin::_convertRewardTokensToDepositTokens");

        // swap to token0
        uint amountOutToken0 = amountIn;
        if (pathRewardToToken0.length != 1) {
            uint[] memory amountsOutToken0 = router.getAmountsOut(amountIn, pathRewardToToken0);
            amountOutToken0 = amountsOutToken0[amountsOutToken0.length - 1];
            router.swapExactTokensForTokens(amountIn, amountOutToken0, pathRewardToToken0, address(this), block.timestamp);
        }

        // swap to token1
        uint amountOutToken1 = amountIn;
        if (pathRewardToToken1.length != 1) {
            uint[] memory amountsOutToken1 = router.getAmountsOut(amountIn, pathRewardToToken1);
            amountOutToken1 = amountsOutToken1[amountsOutToken1.length - 1];
            router.swapExactTokensForTokens(amountIn, amountOutToken1, pathRewardToToken1, address(this), block.timestamp);
        }

        (,,uint liquidity) = router.addLiquidity(
            token0, token1,
            amountOutToken0, amountOutToken1,
            0, 0,
            address(this),
            block.timestamp
        );

        return liquidity;
    }

    function impromptuTokenAggregation(uint minReturnAmountAccepted, bool disableDeposits) external override onlyOwner {
        uint balanceBefore = depositToken.balanceOf(address(this));
        IStakingRewards(stakingContract).exit();
        uint balanceAfter = depositToken.balanceOf(address(this));
        require(balanceAfter - balanceBefore >= minReturnAmountAccepted, "PenguinStrategyForPangolin::impromptuTokenAggregation");
        totalDeposits = balanceAfter;
        emit Reinvest(totalDeposits, totalSupply);
        if (DEPOSITS_ENABLED == true && disableDeposits == true) {
            updateDepositsEnabled(false);
        }
    }

    /**
    * @notice Reward token balance that can be reinvested
    * @dev Staking rewards accurue to contract on each deposit/withdrawal
    * @return Unclaimed rewards, plus contract balance
    */
    function checkReward() public view override returns (uint) {
        return IStakingRewards(stakingContract).earned(address(this));
    }
}










interface IGondolaPool {
    function withdrawAdminFees() external;
    function getA() external view returns (uint256);
    function getAPrecise() external view returns (uint256);
    function getToken(uint8 index) external view returns (address);
    function getTokenIndex(address tokenAddress) external view returns (uint8);
    function getDepositTimestamp(address user) external view returns (uint256);
    function getTokenBalance(uint8 index) external view returns (uint256);
    function getVirtualPrice() external view returns (uint256);
    function calculateSwap(uint8 tokenIndexFrom, uint8 tokenIndexTo, uint256 dx) external view returns (uint256);
    function calculateTokenAmount(address account, uint256[] calldata amounts, bool deposit) external view returns (uint256);
    function calculateRemoveLiquidity(address account, uint256 amount) external view returns (uint256[] memory);
    function calculateRemoveLiquidityOneToken(address account, uint256 tokenAmount, uint8 tokenIndex) external view returns (uint256 availableTokenAmount);
    function calculateCurrentWithdrawFee(address user) external view returns (uint256);
    function getAdminBalance(uint256 index) external view returns (uint256);

    function swap(
        uint8 tokenIndexFrom,
        uint8 tokenIndexTo,
        uint256 dx,
        uint256 minDy,
        uint256 deadline
    ) external returns (uint256);

    function addLiquidity(
        uint256[] calldata amounts,
        uint256 minToMint,
        uint256 deadline
    ) external returns (uint256);

    function removeLiquidity(
        uint256 amount,
        uint256[] calldata minAmounts,
        uint256 deadline
    ) external returns (uint256[] memory);

    function removeLiquidityOneToken(
        uint256 tokenAmount,
        uint8 tokenIndex,
        uint256 minAmount,
        uint256 deadline
    ) external returns (uint256);


    function removeLiquidityImbalance(
        uint256[] calldata amounts,
        uint256 maxBurnAmount,
        uint256 deadline
    ) external returns (uint256);

}


/**
 * @notice StableSwap strategy for Gondola USDT/zUSDT
 */
contract PenguinStrategyForGondolaPool is PefiStrategy {

    IRouter public pangolinRouter = IRouter(0xE54Ca86531e17Ef3616d22Ca28b0D458b6C89106);
    IRouter public zeroRouter = IRouter(0x85995d5f8ee9645cA855e92de16FA62D26398060);
    IGondolaChef public stakingContract;
    IGondolaPool public poolContract;
    address public token0;
    address public token1;
    address[] pathRewardToToken0;
    address[] pathRewardToToken1;
    uint public PID;

    constructor(
        string memory _name,
        address[8] memory _initAddressArray, //depositToken, rewardToken, stakingContract, poolContract, poolCreator, nest, dev, alternate
        uint _pid,
        uint _minTokensToReinvest,
        uint[4] memory _initFeeStructure, //pool creator, nest, dev, alternate
        address[] memory _pathRewardToToken0,
        address[] memory _pathRewardToToken1,
        address _pefiGlobalVariables,
        bool _USE_GLOBAL_PEFI_VARIABLES
    ) {
        name = _name;
        depositToken = IPair(_initAddressArray[0]);
        rewardToken = IERC20(_initAddressArray[1]);
        stakingContract = IGondolaChef(_initAddressArray[2]);
        poolContract = IGondolaPool(_initAddressArray[3]);
        updatePoolCreatorAddress(_initAddressArray[4]);
        updateNestAddress(_initAddressArray[5]);
        updateDevAddress(_initAddressArray[6]);
        updateAlternateAddress(_initAddressArray[7]);
        PID = _pid;
        pathRewardToToken0 = _pathRewardToToken0;
        pathRewardToToken1 = _pathRewardToToken1;
        token0 = _pathRewardToToken0[_pathRewardToToken0.length - 1];
        token1 = _pathRewardToToken1[_pathRewardToToken1.length - 1];
        pefiGlobalVariableContract = PenguinStrategyGlobalVariables(_pefiGlobalVariables);
        USE_GLOBAL_PEFI_VARIABLES = _USE_GLOBAL_PEFI_VARIABLES;
        setAllowances();
        updateMinTokensToReinvest(_minTokensToReinvest);
        updateFeeStructure(_initFeeStructure[0], _initFeeStructure[1], _initFeeStructure[2], _initFeeStructure[3]);
        updateDepositsEnabled(true);

        emit Reinvest(0, 0);
    }

    /**
    * @notice Approve tokens for use in Strategy
    * @dev Restricted to avoid griefing attacks
    */
    function setAllowances() public override onlyOwner {
        depositToken.approve(address(stakingContract), MAX_UINT);
        rewardToken.approve(address(pangolinRouter), MAX_UINT);
        rewardToken.approve(address(zeroRouter), MAX_UINT);
        IERC20(token0).approve(address(poolContract), MAX_UINT);
        IERC20(token1).approve(address(poolContract), MAX_UINT);
    }

    /**
    * @notice Deposit tokens to receive receipt tokens
    * @param amount Amount of tokens to deposit
    */
    function deposit(uint amount) external override {
        _deposit(msg.sender, amount);
    }

    /**
    * @notice Deposit using Permit
    * @param amount Amount of tokens to deposit
    * @param deadline The time at which to expire the signature
    * @param v The recovery byte of the signature
    * @param r Half of the ECDSA signature pair
    * @param s Half of the ECDSA signature pair
    */
    function depositWithPermit(uint amount, uint deadline, uint8 v, bytes32 r, bytes32 s) external override {
        depositToken.permit(msg.sender, address(this), amount, deadline, v, r, s);
        _deposit(msg.sender, amount);
    }

    function depositFor(address account, uint amount) external override {
        _deposit(account, amount);
    }

    function _deposit(address account, uint amount) internal {
        require(DEPOSITS_ENABLED == true, "PenguinStrategyForGondolaPool::_deposit");
        if (MAX_TOKENS_TO_DEPOSIT_WITHOUT_REINVEST > 0) {
            uint unclaimedRewards = checkReward();
            if (unclaimedRewards > MAX_TOKENS_TO_DEPOSIT_WITHOUT_REINVEST) {
                _reinvest(unclaimedRewards);
            }
        }
        require(depositToken.transferFrom(msg.sender, address(this), amount));
        _stakeDepositTokens(amount);
        _mint(account, getSharesForDepositTokens(amount));
        totalDeposits += amount;
        emit Deposit(account, amount);
    }

    function withdraw(uint amount) external override {
        uint depositTokenAmount = getDepositTokensForShares(amount);
        if (depositTokenAmount > 0) {
            _withdrawDepositTokens(depositTokenAmount);
            require(depositToken.transfer(msg.sender, depositTokenAmount), "PenguinStrategyForGondolaPool::withdraw");
            _burn(msg.sender, amount);
            totalDeposits -= depositTokenAmount;
            emit Withdraw(msg.sender, depositTokenAmount);
        }
    }

    function _withdrawDepositTokens(uint amount) private {
        require(amount > 0, "PenguinStrategyForGondolaPool::_withdrawDepositTokens");
        stakingContract.withdraw(PID, amount);
    }

    function reinvest() external override onlyEOA {
        uint unclaimedRewards = checkReward();
        require(unclaimedRewards >= MIN_TOKENS_TO_REINVEST, "PenguinStrategyForGondolaPool::reinvest");
        _reinvest(unclaimedRewards);
    }

    /**
    * @notice Reinvest rewards from staking contract to deposit tokens
    * @dev Reverts if the expected amount of tokens are not returned from `stakingContract`
    * @param amount deposit tokens to reinvest
    */
    function _reinvest(uint amount) internal {
        stakingContract.deposit(PID, 0);

        uint devFee = (amount * DEV_FEE_BIPS()) / BIPS_DIVISOR;
        if (devFee > 0) {
            require(rewardToken.transfer(devAddress(), devFee), "PenguinStrategyForPangolin::_reinvest, dev");
        }

        uint nestFee = (amount * NEST_FEE_BIPS()) / BIPS_DIVISOR;
        if (nestFee > 0) {
            require(rewardToken.transfer(nestAddress(), nestFee), "PenguinStrategyForPangolin::_reinvest, nest");
        }

        uint poolCreatorFee = (amount * POOL_CREATOR_FEE_BIPS()) / BIPS_DIVISOR;
        if (poolCreatorFee > 0) {
            require(rewardToken.transfer(poolCreatorAddress, poolCreatorFee), "PenguinStrategyForPangolin::_reinvest, poolCreator");
        }

        uint alternateFee = (amount * ALTERNATE_FEE_BIPS()) / BIPS_DIVISOR;
        if (alternateFee > 0) {
            require(rewardToken.transfer(alternateAddress(), alternateFee), "PenguinStrategyForPangolin::_reinvest, alternate");
        }

        uint depositTokenAmount = _convertRewardTokensToDepositTokens(
            (amount - (devFee + nestFee + poolCreatorFee + alternateFee))
        );

        _stakeDepositTokens(depositTokenAmount);
        totalDeposits += depositTokenAmount;

        emit Reinvest(totalDeposits, totalSupply);
    }


    function _stakeDepositTokens(uint amount) private {
        require(amount > 0, "PenguinStrategyForGondolaPool::_stakeDepositTokens");
        stakingContract.deposit(PID, amount);
    }

    function checkReward() public override view returns (uint) {
        uint pendingReward = stakingContract.pendingGondola(PID, address(this));
        uint contractBalance = rewardToken.balanceOf(address(this));
        return (pendingReward + contractBalance);
    }

    /**
    * @notice Converts reward tokens to deposit tokens
    * @dev Always converts through router; there are no price checks enabled
    * @return deposit tokens received
    */
    function _convertRewardTokensToDepositTokens(uint amount) private returns (uint) {
        require(amount > 0, "PenguinStrategyForGondolaPool::_convertRewardTokensToDepositTokens");

        uint[] memory liquidityAmounts = new uint[](2);
        // find route for bonus token
        if (poolContract.getTokenBalance(0) < poolContract.getTokenBalance(1)) {
            // convert to token0
            uint[] memory amountsOutToken = pangolinRouter.getAmountsOut(amount, pathRewardToToken0);
            uint amountOutToken = amountsOutToken[amountsOutToken.length - 1];
            pangolinRouter.swapExactTokensForTokens(amount, amountOutToken, pathRewardToToken0, address(this), block.timestamp);
            liquidityAmounts[0] = amountOutToken;
        }
        else {
            // convert to token1
            uint[] memory amountsOutToken = zeroRouter.getAmountsOut(amount, pathRewardToToken1);
            uint amountOutToken = amountsOutToken[amountsOutToken.length - 1];
            zeroRouter.swapExactTokensForTokens(amount, amountOutToken, pathRewardToToken1, address(this), block.timestamp);
            liquidityAmounts[1] = amountOutToken;
        }

        uint liquidity = poolContract.addLiquidity(liquidityAmounts, 0, block.timestamp);
        return liquidity;
    }

    /**
    * @notice Estimate recoverable balance
    * @return deposit tokens
    */
    function estimateDeployedBalance() external view returns (uint) {
        (uint depositBalance, ) = stakingContract.userInfo(PID, address(this));
        return depositBalance;
    }

    function impromptuTokenAggregation(uint minReturnAmountAccepted, bool disableDeposits) external override onlyOwner {
        uint balanceBefore = depositToken.balanceOf(address(this));
        stakingContract.emergencyWithdraw(PID);
        uint balanceAfter = depositToken.balanceOf(address(this));
        require((balanceAfter - balanceBefore) >= minReturnAmountAccepted, "PenguinStrategyForGondolaPool::impromptuTokenAggregation");
        totalDeposits = balanceAfter;
        emit Reinvest(totalDeposits, totalSupply);
        if (DEPOSITS_ENABLED == true && disableDeposits == true) {
            updateDepositsEnabled(false);
        }
    }
}
