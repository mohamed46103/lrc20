from contextlib import contextmanager
from typing import Generator, Optional

import grpc
from google.protobuf import empty_pb2

from .protos import service_pb2 as pb
from .protos import service_pb2_grpc as pb_grpc
from .protos import types_pb2


class Lrc20GrpcClient:
    """gRPC client for LRC20 token operations.

    Provides methods for sending, listing and verifying LRC20 transactions.
    Can be used as a context manager for long-lived connections.

    Examples:
        Long-lived connections (preferred for multiple requests):
        >>> try:
        ...     with Lrc20GrpcClient("localhost:50051") as client:
        ...         tx1 = client.send_spark_tx(...args)
        ...         tx2 = client.send_spark_tx(...args)
        ...         tx3 = client.send_spark_tx(...args)
        Connection is closed when exiting with block.

        Temporary connections (each request opens/closes a new connection):
        >>> client = Lrc20GrpcClient("localhost:50051")
        >>> try:
        ...     tx_hash = client.send_spark_tx(...args)
    """

    def __init__(self, grpc_url: str, timeout: int = 30):
        """Initialize LRC20 gRPC client.

        Args:
            target: gRPC server address (e.g. "localhost:50051")
            timeout: Request timeout in seconds
        """
        self._grpc_url = grpc_url.rstrip("/")
        self._timeout = timeout
        self._channel: Optional[grpc.Channel] = None
        self._stub: Optional[pb_grpc.SparkServiceStub] = None

    def __enter__(self) -> "Lrc20GrpcClient":
        """Context manager for long-lived connections"""
        self._channel = grpc.insecure_channel(target=self._grpc_url)
        self._stub = pb_grpc.SparkServiceStub(self._channel)
        return self

    def __exit__(self):
        if self._channel:
            self._channel.close()
            self._channel = None
            self._stub = None

    def get_spark_tx(
        self, final_token_transaction_hash: bytes
    ) -> pb.GetSparkTxResponse:
        """Get a Spark transaction by its hash.

        Args:
            tx_hash: Transaction hash in bytes

        Returns:
            types_pb2.TokenTransaction: The transaction if found
        """
        with self._temp_channel() as stub:
            try:
                request = pb.GetSparkTxRequest(
                    final_token_transaction_hash=final_token_transaction_hash
                )
                return stub.GetSparkTx(request, timeout=self._timeout)
            except grpc.RpcError as e:
                self._handle_grpc_error(e)

    def send_spark_tx(
        self,
        identity_public_key: bytes,
        final_token_transaction: types_pb2.TokenTransaction,
    ) -> empty_pb2.Empty:
        """Send a Spark transaction.

        Args:
            identity_public_key: Public key of the identity
            final_token_transaction: Final token transaction

        Returns:
            google.protobuf.Empty: Empty response
        """
        with self._temp_channel() as stub:
            try:
                request = pb.SendSparkTxRequest(
                    identity_public_key=identity_public_key,
                    final_token_transaction=final_token_transaction,
                )
                return stub.SendSparkTx(request, timeout=self._timeout)
            except grpc.RpcError as e:
                self._handle_grpc_error(e)

    def send_spark_signature(
        self, signature_data: types_pb2.SparkSignatureData
    ) -> empty_pb2.Empty:
        """Send a Spark signature.

        Args:
            signature_data: The SparkSignatureData protobuf message

        Returns:
            google.protobuf.Empty: Empty response indicating success
        """
        with self._temp_channel() as stub:
            try:
                request = pb.SendSparkSignatureRequest(signature_data=signature_data)
                return stub.SendSparkSignature(request, timeout=self._timeout)
            except grpc.RpcError as e:
                self._handle_grpc_error(e)

    def verify_spark_tx_request(
        self, final_token_transaction: types_pb2.TokenTransaction
    ) -> pb.VerifySparkTxResponse:
        """Verifies a Spark transaction.

        Args:
            final_token_transaction: Final token transaction

        Returns:
            VerifySparkTxResponse: Response with is_valid field
        """
        with self._temp_channel() as stub:
            try:
                request = pb.VerifySparkTxRequest(
                    final_token_transaction=final_token_transaction
                )
                return stub.VerifySparkTx(request, timeout=self._timeout)
            except grpc.RpcError as e:
                self._handle_grpc_error(e)

    def list_spark_txs(
        self, page_token: Optional[bytes] = None, page_size: Optional[int] = None
    ) -> pb.ListSparkTxsResponse:
        """List Spark transactions with pagination.

        Args:
            page_token: Pagination token
            page_size: Number of transactions per page

            ListSparkTxsResponse:
                - txs: List[TokenTransactionResponse], where each response has:
                    - txid: bytes - Transaction ID
                    - finalized: bool - Whether the transaction is finalized
                    - tx: TokenTransaction - The full transaction details
                - nextPageToken: Optional[bytes] - Token to fetch next page, None if no more pages
        """
        with self._temp_channel() as stub:
            try:
                request = pb.ListSparkTxsRequest(
                    page_token=page_token, page_size=page_size
                )
                return stub.ListSparkTxs(request, timeout=self._timeout)
            except grpc.RpcError as e:
                self._handle_grpc_error(e)

    def reconnect(self):
        """Recreate channel if connection is lost"""
        self._channel = grpc.insecure_channel(self._grpc_url)
        self._stub = pb_grpc.SparkServiceStub(self._channel)

    @staticmethod
    def _handle_grpc_error(e: grpc.RpcError):
        """Handle gRPC errors with appropriate Python exceptions."""
        if e.code() == grpc.StatusCode.UNAVAILABLE:
            raise ConnectionError("gRPC service unavailable")
        elif e.code() == grpc.StatusCode.INVALID_ARGUMENT:
            raise ValueError(e.details())
        raise e

    @contextmanager
    def _temp_channel(self) -> Generator[pb_grpc.SparkServiceStub, None, None]:
        if self._stub:
            yield self._stub
        else:
            channel = grpc.insecure_channel(self._grpc_url)
            stub = pb_grpc.SparkServiceStub(channel)
            try:
                yield stub
            finally:
                channel.close()
