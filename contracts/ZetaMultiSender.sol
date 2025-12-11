// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

contract ZetaMultiSender is ReentrancyGuard {
    using SafeERC20 for IERC20;

    event MultiSendEth(uint256 total, address indexed sender);
    event MultiSendToken(address indexed token, uint256 total, address indexed sender);

    function disperseEther(address[] calldata recipients, uint256[] calldata values) external payable nonReentrant {
        require(recipients.length == values.length, "Arrays length mismatch");
        
        uint256 total = 0;
        for (uint256 i = 0; i < recipients.length; i++) {
            total += values[i];
        }
        require(msg.value >= total, "Insufficient ETH sent");

        for (uint256 i = 0; i < recipients.length; i++) {
            (bool success, ) = recipients[i].call{value: values[i]}("");
            require(success, "Transfer failed");
        }
        
        uint256 balance = address(this).balance;
        if (balance > 0) {
            (bool successRefund, ) = payable(msg.sender).call{value: balance}("");
            require(successRefund, "Refund failed");
        }

        emit MultiSendEth(total, msg.sender);
    }

    function disperseToken(IERC20 token, address[] calldata recipients, uint256[] calldata values) external nonReentrant {
        require(recipients.length == values.length, "Arrays length mismatch");
        
        uint256 total = 0;
        for (uint256 i = 0; i < recipients.length; i++) {
            total += values[i];
        }

        token.safeTransferFrom(msg.sender, address(this), total);

        for (uint256 i = 0; i < recipients.length; i++) {
            token.safeTransfer(recipients[i], values[i]);
        }

        emit MultiSendToken(address(token), total, msg.sender);
    }
}