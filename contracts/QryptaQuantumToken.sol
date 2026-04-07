// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// OpenZeppelin v5 (Remix-friendly raw imports)
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Pausable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
/**
 * =================================================================================================
 *  ⚠️  QRYPTA LABS — PROPRIETARY / CONFIDENTIAL SOURCE CODE
 * =================================================================================================
 *  This smart contract and all of its contents (code, logic, architecture, and design) are the
 *  exclusive property of QRYPTA LABS.
 *
 *  PROHIBITED: copying, reproducing, duplicating, modifying, distributing, publishing, selling,
 *  sublicensing, or reusing this code — in whole or in part — without explicit written permission
 *  from QRYPTA LABS.
 *
 *  Any unauthorized reproduction or use may constitute copyright infringement, misappropriation,
 *  and/or unfair competition, and may result in civil and criminal legal action, including claims
 *  for damages.
 *
 *  Official contact: contact@qryptalabs.com
 *
 *  If you have obtained access to this code without authorization, you MUST cease all use immediately.
 * =================================================================================================
 */

/**
 * SP1 gateway/verifier interface:
 * MUST revert if proof is invalid.
 */
interface ISP1Verifier {
    function verifyProof(
        bytes32 programVKey,
        bytes calldata publicValues,
        bytes calldata proofBytes
    ) external view;
}

contract QryptaQuantumToken is ERC20Pausable, Ownable, AccessControl {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    // -------- Roles --------
    bytes32 public constant BANK_OPERATOR_ROLE = keccak256("BANK_OPERATOR_ROLE");

    // -------- PQC/ZK State --------
    mapping(address => bytes32) public quantumPublicKeyRoots; // PQC root/commitment per user
    mapping(address => uint256) public pqcNonces;             // anti-replay nonce per user
    mapping(address => bool) public pqcOnly;                  // if true => must use ZK route (bank-grade)

    ISP1Verifier public sp1Gateway;
    bytes32 public programVKey;        // SP1 Verification Key Hash (bytes32)
    uint256 public pqcThreshold;       // if amount >= threshold => require ZK route (when thresholdEnabled=true)
    bool public thresholdEnabled = false;

    // -------- Hybrid attesters  --------
    mapping(address => bool) public isAttester;
    uint8 public attesterQuorum; // M-of-N required
    bytes32 private constant ATTESTATION_DOMAIN = keccak256("QRYPTA_ATTESTATION_V1");

    // -------- Fees --------
    uint256 public burnRateBps = 25; // 0.25%
    address public treasuryWallet;

    // -------- Compliance toggles --------
    bool public kycEnabled = false;
    bool public denylistEnabled = true;

    mapping(address => bool) public kycAllowlist;
    mapping(address => bool) public denylist;

    // -------- Freeze wallets --------
    mapping(address => bool) public frozen;
    event WalletFrozen(address indexed user);
    event WalletUnfrozen(address indexed user);

    // -------- PublicValues struct --------
    struct PublicValues {
        address from;
        address to;
        uint256 amount;
        uint256 nonce;
        bytes32 pqcRoot;
        bytes32 isoRefHash;
        uint256 chainId;
        address token;
        uint256 deadline;
    }

    // -------- Events --------
    event ISO20022Transfer(
        address indexed from,
        address indexed to,
        uint256 amountGross,
        uint256 amountNet,
        uint256 burnAmount,
        bytes32 indexed isoRefHash,
        string isoReference
    );

    event QuantumKeyRegistered(address indexed user, bytes32 pqcRoot);
    event Sp1GatewayUpdated(address indexed newGateway);
    event ProgramVKeyUpdated(bytes32 newVKey);
    event PQCThresholdUpdated(uint256 newThreshold);
    event ThresholdEnabledUpdated(bool enabled);
    event BurnRateUpdated(uint256 newBurnRateBps);

    event AttesterSet(address indexed attester, bool allowed);
    event AttesterQuorumUpdated(uint8 newQuorum);
    event PqcOnlySet(address indexed user, bool enabled);

    event KycModeUpdated(bool enabled);
    event DenylistModeUpdated(bool enabled);
    event KycSet(address indexed user, bool allowed);
    event DenySet(address indexed user, bool denied);

    // -------- Errors --------
    error PQCRequired();
    error NoPqcKey();
    error BadRoot();
    error ProgramVKeyNotSet();
    error Denied();
    error KycRequired();
    error FrozenWallet();

    error PVFromMismatch();
    error PVToMismatch();
    error PVAmountMismatch();
    error PVNonceMismatch();
    error PVRootMismatch();
    error PVIsoHashMismatch();
    error PVChainIdMismatch();
    error PVTokenMismatch();
    error PVExpired();

    error AttestedNotAllowed();
    error BadQuorum();
    error NotEnoughAttesters();
    error InvalidAttesterSig();
    error AttesterSigOrder();

    /**
     * Constructor
     */
    constructor(
        address _treasury,
        address _sp1Gateway,
        bytes32 _programVKey,
        uint256 _pqcThreshold,
        address[] memory initialAttesters,
        uint8 quorum
    )
        ERC20("QRYPTA", "QRYP")
        Ownable(msg.sender)
    {
        require(_sp1Gateway != address(0), "SP1=0");
        treasuryWallet = _treasury;
        sp1Gateway = ISP1Verifier(_sp1Gateway);
        programVKey = _programVKey;
        pqcThreshold = _pqcThreshold;

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(BANK_OPERATOR_ROLE, msg.sender);

        if (quorum == 0) revert BadQuorum();
        if (initialAttesters.length < quorum) revert BadQuorum();
        attesterQuorum = quorum;

        for (uint256 i = 0; i < initialAttesters.length; i++) {
            address a = initialAttesters[i];
            require(a != address(0), "attester=0");
            isAttester[a] = true;
            emit AttesterSet(a, true);
        }
        emit AttesterQuorumUpdated(quorum);

        _mint(msg.sender, 1_000_000_000 * 10 ** decimals());
    }

    // =========================
    // Emergency controls
    // =========================
    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }

    // Freeze/unfreeze convenience wrappers
    function freeze(address user) external onlyOwner {
        frozen[user] = true;
        emit WalletFrozen(user);
    }

    function unfreeze(address user) external onlyOwner {
        frozen[user] = false;
        emit WalletUnfrozen(user);
    }

    // =========================
    // Mint / Burn controls
    // =========================
    function mint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
    }

    function burn(uint256 amount) external {
        _burn(_msgSender(), amount);
    }

    function burnFrom(address from, uint256 amount) external {
        uint256 currentAllowance = allowance(from, _msgSender());
        require(currentAllowance >= amount, "Allowance low");
        _approve(from, _msgSender(), currentAllowance - amount);
        _burn(from, amount);
    }

    // =========================
    // Admin / Governance
    // =========================
    function setSp1Gateway(address newGateway) external onlyOwner {
        require(newGateway != address(0), "SP1=0");
        sp1Gateway = ISP1Verifier(newGateway);
        emit Sp1GatewayUpdated(newGateway);
    }

    function setProgramVKey(bytes32 newVKey) external onlyOwner {
        programVKey = newVKey;
        emit ProgramVKeyUpdated(newVKey);
    }

    function setPqcThreshold(uint256 newThreshold) external onlyOwner {
        pqcThreshold = newThreshold;
        emit PQCThresholdUpdated(newThreshold);
    }

    function setThresholdEnabled(bool enabled) external onlyOwner {
        thresholdEnabled = enabled;
        emit ThresholdEnabledUpdated(enabled);
    }

    function setPqcOnly(address user, bool enabled) external onlyOwner {
        pqcOnly[user] = enabled;
        emit PqcOnlySet(user, enabled);
    }

    function setBurnRateBps(uint256 newBps) external onlyOwner {
        require(newBps <= 500, "Too high");
        burnRateBps = newBps;
        emit BurnRateUpdated(newBps);
    }

    function setAttester(address attester, bool allowed) external onlyOwner {
        require(attester != address(0), "attester=0");
        isAttester[attester] = allowed;
        emit AttesterSet(attester, allowed);
    }

    function setAttesterQuorum(uint8 newQuorum) external onlyOwner {
        if (newQuorum == 0) revert BadQuorum();
        attesterQuorum = newQuorum;
        emit AttesterQuorumUpdated(newQuorum);
    }

    function setKycEnabled(bool enabled) external onlyOwner {
        kycEnabled = enabled;
        emit KycModeUpdated(enabled);
    }

    function setDenylistEnabled(bool enabled) external onlyOwner {
        denylistEnabled = enabled;
        emit DenylistModeUpdated(enabled);
    }

    function setKyc(address user, bool allowed) external onlyRole(BANK_OPERATOR_ROLE) {
        kycAllowlist[user] = allowed;
        emit KycSet(user, allowed);
    }

    function setDenied(address user, bool deniedStatus) external onlyRole(BANK_OPERATOR_ROLE) {
        denylist[user] = deniedStatus;
        emit DenySet(user, deniedStatus);
    }

    // =========================
    // PQC registration
    // =========================
    function registerQuantumKey(bytes32 pqcPublicKeyRoot) external {
        if (pqcPublicKeyRoot == bytes32(0)) revert BadRoot();
        quantumPublicKeyRoots[msg.sender] = pqcPublicKeyRoot;
        emit QuantumKeyRegistered(msg.sender, pqcPublicKeyRoot);
    }

    // =========================
    // ERC20 overrides 
    // =========================
    function transfer(address recipient, uint256 amount) public override returns (bool) {
        if (pqcOnly[_msgSender()]) revert PQCRequired();
        if (thresholdEnabled && amount >= pqcThreshold) revert PQCRequired();

        _applyBurnAndTransfer(_msgSender(), recipient, amount, bytes32(0), "");
        return true;
    }

    function transferFrom(address from, address recipient, uint256 amount) public override returns (bool) {
        if (pqcOnly[from]) revert PQCRequired();
        if (thresholdEnabled && amount >= pqcThreshold) revert PQCRequired();

        uint256 currentAllowance = allowance(from, _msgSender());
        require(currentAllowance >= amount, "Allowance low");
        _approve(from, _msgSender(), currentAllowance - amount);

        _applyBurnAndTransfer(from, recipient, amount, bytes32(0), "");
        return true;
    }

    // =========================
    // PQC Transfer (ZK proof) - bank grade
    // =========================
    function quantumTransferZK(
        address recipient,
        uint256 amount,
        bytes calldata publicValues,
        bytes calldata proofBytes,
        string calldata isoReference
    ) external returns (bool) {
        bytes32 registeredRoot = quantumPublicKeyRoots[_msgSender()];
        if (registeredRoot == bytes32(0)) revert NoPqcKey();
        if (programVKey == bytes32(0)) revert ProgramVKeyNotSet();

        bytes32 isoRefHashLocal = keccak256(bytes(isoReference));

        PublicValues memory pv = _decodePublicValues(publicValues);
        _validatePublicValues(pv, _msgSender(), recipient, amount, registeredRoot, isoRefHashLocal);

        sp1Gateway.verifyProof(programVKey, publicValues, proofBytes);

        pqcNonces[_msgSender()] = pv.nonce + 1;

        _applyBurnAndTransfer(_msgSender(), recipient, amount, isoRefHashLocal, isoReference);
        return true;
    }

    // =========================
    // PQC Transfer 
    // =========================
    function attestedQuantumTransfer(
        address recipient,
        uint256 amount,
        bytes calldata publicValues,
        string calldata isoReference,
        bytes[] calldata attesterSignatures
    ) external returns (bool) {
        if (pqcOnly[_msgSender()]) revert AttestedNotAllowed();
        if (thresholdEnabled && amount >= pqcThreshold) revert AttestedNotAllowed();

        bytes32 registeredRoot = quantumPublicKeyRoots[_msgSender()];
        if (registeredRoot == bytes32(0)) revert NoPqcKey();
        if (programVKey == bytes32(0)) revert ProgramVKeyNotSet();

        bytes32 isoRefHashLocal = keccak256(bytes(isoReference));

        PublicValues memory pv = _decodePublicValues(publicValues);
        _validatePublicValues(pv, _msgSender(), recipient, amount, registeredRoot, isoRefHashLocal);

        bytes32 publicValuesHash = keccak256(publicValues);
        bytes32 digest = _attestationDigest(programVKey, publicValuesHash);

        _checkAttesterQuorum(digest, attesterSignatures);

        pqcNonces[_msgSender()] = pv.nonce + 1;

        _applyBurnAndTransfer(_msgSender(), recipient, amount, isoRefHashLocal, isoReference);
        return true;
    }

    // =========================
    // Bank operator transfer 
    // =========================
    function bankTransfer(
        address from,
        address recipient,
        uint256 amount,
        string calldata isoReference
    ) external onlyRole(BANK_OPERATOR_ROLE) returns (bool) {
        uint256 currentAllowance = allowance(from, _msgSender());
        require(currentAllowance >= amount, "Allowance low");
        _approve(from, _msgSender(), currentAllowance - amount);

        bytes32 isoRefHashLocal = keccak256(bytes(isoReference));
        _applyBurnAndTransfer(from, recipient, amount, isoRefHashLocal, isoReference);
        return true;
    }

    // =========================
    // Internal: decode + validate PV
    // =========================
    function _decodePublicValues(bytes calldata publicValues) internal pure returns (PublicValues memory pv) {
        pv = abi.decode(publicValues, (PublicValues));
    }

    function _validatePublicValues(
        PublicValues memory pv,
        address expectedFrom,
        address expectedTo,
        uint256 expectedAmount,
        bytes32 expectedRoot,
        bytes32 expectedIsoHash
    ) internal view {
        if (pv.from != expectedFrom) revert PVFromMismatch();
        if (pv.to != expectedTo) revert PVToMismatch();
        if (pv.amount != expectedAmount) revert PVAmountMismatch();

        if (pv.nonce != pqcNonces[expectedFrom]) revert PVNonceMismatch();
        if (pv.pqcRoot != expectedRoot) revert PVRootMismatch();
        if (pv.isoRefHash != expectedIsoHash) revert PVIsoHashMismatch();

        if (pv.chainId != block.chainid) revert PVChainIdMismatch();
        if (pv.token != address(this)) revert PVTokenMismatch();
        if (block.timestamp > pv.deadline) revert PVExpired();
    }

    // =========================
    // Internal: attester digest + quorum
    // =========================
    function _attestationDigest(bytes32 _programVKey, bytes32 publicValuesHash) internal view returns (bytes32) {
        bytes32 inner = keccak256(
            abi.encode(
                ATTESTATION_DOMAIN,
                _programVKey,
                publicValuesHash,
                block.chainid,
                address(this)
            )
        );
        return inner.toEthSignedMessageHash(); // EIP-191
    }

    function _checkAttesterQuorum(bytes32 digest, bytes[] calldata sigs) internal view {
        uint256 n = sigs.length;
        if (n < attesterQuorum) revert NotEnoughAttesters();

        address last = address(0);
        uint256 valid = 0;

        for (uint256 i = 0; i < n; i++) {
            address recovered = digest.recover(sigs[i]);

            if (recovered <= last) revert AttesterSigOrder();
            last = recovered;

            if (!isAttester[recovered]) revert InvalidAttesterSig();

            valid++;
            if (valid == attesterQuorum) return;
        }

        revert NotEnoughAttesters();
    }

    // =========================
    // Burn + transfer helper
    // =========================
    function _applyBurnAndTransfer(
        address from,
        address to,
        uint256 amount,
        bytes32 isoRefHash,
        string memory isoReference
    ) internal {
        uint256 burnAmount = (amount * burnRateBps) / 10_000;
        uint256 finalAmount = amount - burnAmount;

        if (burnAmount > 0) _burn(from, burnAmount);
        _transfer(from, to, finalAmount);

        if (isoRefHash != bytes32(0)) {
            emit ISO20022Transfer(from, to, amount, finalAmount, burnAmount, isoRefHash, isoReference);
        }
    }

    // =========================
    // HARD STOP: pause + freeze + compliance applied to ALL token movements
    // Blocks swaps, transfers, transferFrom, quantum, bankTransfer, mint, burn.
    // =========================
    function _update(address from, address to, uint256 value)
        internal
        override(ERC20Pausable)
        whenNotPaused
    {
        if (from != address(0) && frozen[from]) revert FrozenWallet();
        if (to != address(0) && frozen[to]) revert FrozenWallet();

        // If you want compliance checks globally, enable here:
        if (from != address(0) && to != address(0)) {
            // deny/kyc
            if (denylistEnabled) {
                if (denylist[from] || denylist[to]) revert Denied();
            }
            if (kycEnabled) {
                if (!kycAllowlist[from] || !kycAllowlist[to]) revert KycRequired();
            }
        }

        super._update(from, to, value);
    }
}
