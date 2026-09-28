const { createPublicClient, http, formatUnits } = require('viem');
const { base } = require('viem/chains');

// إعداد الاتصال بالشبكة
const client = createPublicClient({
  chain: base,
  transport: http('https://mainnet.base.org')
});

const BINANCE_DEPOSIT_ADDRESS = '0xb19c1a05c1efb6f0c69bbe67190b049fee087884';
// عنوان عقد USDC الرسمي على شبكة Base
const USDC_ADDRESS = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';

// واجهة مصغرة (ABI) لجلب الرصيد
const ERC20_ABI = [
  {
    constant: true,
    inputs: [{ name: '_owner', type: 'address' }],
    name: 'balanceOf',
    outputs: [{ name: 'balance', type: 'uint256' }],
    type: 'function',
  }
];

async function checkBinanceDepositWallet() {
  try {
    console.log(`[🔍] جلب الأرصدة لعنوان بينانس: ${BINANCE_DEPOSIT_ADDRESS}`);
    
    // 1. جلب الرصيد الأساسي (ETH)
    const ethBalance = await client.getBalance({
      address: BINANCE_DEPOSIT_ADDRESS,
    });

    // 2. جلب رصيد USDC (يعتمد 6 خانات عشرية)
    const usdcBalance = await client.readContract({
      address: USDC_ADDRESS,
      abi: ERC20_ABI,
      functionName: 'balanceOf',
      args: [BINANCE_DEPOSIT_ADDRESS],
    });

    console.log(`----------------------------------------`);
    console.log(`[💰] رصيد ETH الأساسي: ${formatUnits(ethBalance, 18)} ETH`);
    console.log(`[💵] رصيد USDC المتاح: ${formatUnits(usdcBalance, 6)} USDC`);
    console.log(`----------------------------------------`);

    const blockNumber = await client.getBlockNumber();
    console.log(`[block] رقم الكتلة الحالي على الشبكة: ${blockNumber}`);

  } catch (error) {
    console.error(`[❌] حدث خطأ أثناء فحص الأرصدة:`, error.message);
  }
}

checkBinanceDepositWallet();
