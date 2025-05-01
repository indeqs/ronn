// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

/**
 * @title InspectionLogger
 * @dev Basic contract to store inspection record hashes.
 * WARNING: This is a simplified placeholder for demonstration.
 * Real-world contracts need access control, events, error handling, etc.
 */
contract InspectionLogger {
    // Mapping from inspection ID (from our web app DB) to its data hash
    mapping(uint256 => string) public inspectionHashes;
    // Mapping from inspection ID to the block timestamp it was recorded
    mapping(uint256 => uint256) public recordTimestamps;

    // Event emitted when an inspection is recorded
    event InspectionRecorded(
        uint256 indexed inspectionId,
        string dataHash,
        uint256 timestamp
    );

    // Address of the owner/server authorized to record inspections
    // TODO: Implement proper access control (e.g., Ownable, RoleBasedAccessControl)
    address public owner;

    modifier onlyOwner() {
        // require(msg.sender == owner, "Caller is not the owner"); // Basic check
        _;
    }

    constructor() {
        owner = msg.sender; // Set deployer as owner (replace with secure method)
    }

    /**
     * @dev Records the hash of an inspection data.
     * @param _inspectionId The ID of the inspection from the web application database.
     * @param _dataHash The hash representing the inspection data.
     */
    // In a real scenario, only authorized address (server/engineer wallet) should call this
    function recordInspection(
        uint256 _inspectionId,
        string memory _dataHash
    ) public /*onlyOwner*/ {
        // Basic check: ensure not overwriting (or allow updates based on logic)
        // require(bytes(inspectionHashes[_inspectionId]).length == 0, "Inspection already recorded");

        inspectionHashes[_inspectionId] = _dataHash;
        recordTimestamps[_inspectionId] = block.timestamp;

        emit InspectionRecorded(_inspectionId, _dataHash, block.timestamp);
    }

    /**
     * @dev Retrieves the hash for a given inspection ID.
     * @param _inspectionId The ID of the inspection.
     * @return The recorded data hash string.
     */
    function getInspectionHash(
        uint256 _inspectionId
    ) public view returns (string memory) {
        return inspectionHashes[_inspectionId];
    }

    /**
     * @dev Retrieves the timestamp for a given inspection ID record.
     * @param _inspectionId The ID of the inspection.
     * @return The block timestamp when the record was added.
     */
    function getRecordTimestamp(
        uint256 _inspectionId
    ) public view returns (uint256) {
        return recordTimestamps[_inspectionId];
    }
}
