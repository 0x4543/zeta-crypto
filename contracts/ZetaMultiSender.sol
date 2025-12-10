pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);
}

contract ZetaMultiSender {
    event MultiSendEth(uint256 total, address indexed sender);
    event MultiSendToken(address indexed token, uint256 total, address indexed sender);

    function disperseEther(address[] calldata recipients, uint256[] calldata values) external payable {
        require(recipients.length == values.length, "Arrays length mismatch");
        
        for (uint256 i = 0; i < recipients.length; i++) {
            (bool success, ) = recipients[i].call{value: values[i]}("");
            require(success, "Transfer failed");
        }
        
        uint256 balance = address(this).balance;
        if (balance > 0) {
            payable(msg.sender).transfer(balance);
        }

        emit MultiSendEth(msg.value, msg.sender);
    }

    function disperseToken(address token, address[] calldata recipients, uint256[] calldata values) external {
        require(recipients.length == values.length, "Arrays length mismatch");
        
        uint256 total = 0;
        for (uint256 i = 0; i < recipients.length; i++) {
            require(IERC20(token).transferFrom(msg.sender, recipients[i], values[i]), "Transfer failed");
            total += values[i];
        }

        emit MultiSendToken(token, total, msg.sender);
    }
}