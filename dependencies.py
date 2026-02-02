# /dependencies.py (Corrected)
from secret_sdk.client.lcd import LCDClient, AsyncLCDClient # Add AsyncLCDClient here
from secret_sdk.key.mnemonic import MnemonicKey
import config

# --- Secret Network Client ---
secret_client = LCDClient(url=config.SECRET_LCD_URL, chain_id=config.SECRET_CHAIN_ID)
wallet = secret_client.wallet(MnemonicKey(mnemonic=config.WALLET_KEY))

# --- Async Secret Network Client ---
async def get_async_secret_client():
    """
    This dependency injector uses the 'async with' pattern to create, yield,
    and reliably close an AsyncLCDClient for each API request.
    """
    async with AsyncLCDClient(chain_id=config.SECRET_CHAIN_ID, url=config.SECRET_LCD_URL) as client:
        yield client