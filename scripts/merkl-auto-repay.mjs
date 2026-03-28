/**
 * merkl-auto-repay.mjs
 *
 * 자동화 파이프라인:
 *   1. Merkl API → 클레임 가능한 WLFI 확인
 *   2. WLFI 클레임 (Merkl Distributor)
 *   3. WLFI → USDC 스왑 (Uniswap v3)
 *   4. USDC 리페이 (Dolomite)
 *
 * 실행:
 *   node scripts/merkl-auto-repay.mjs
 *
 * 필요한 패키지:
 *   npm install ethers axios dotenv
 */

import { ethers } from 'ethers';
import axios from 'axios';
import dotenv from 'dotenv';
dotenv.config();

// ─── 설정 ──────────────────────────────────────────────────────────────────

const WALLET  = '0x03648c897f9adBd74Ba2dFCd0A0073E7A1754d80';
const RPC_URL = 'https://ethereum.publicnode.com';

// 컨트랙트 주소
const MERKL_DISTRIBUTOR = '0x3Ef3D8bA38EBe18DB133cEc108f4D14CE00Dd9Ae';
const WLFI              = '0xda5e1988097297dcdc1f90d4dfe7909e847cbef6';
const USDC              = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48';
const UNISWAP_ROUTER    = '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45';
const DOLOMITE_ROUTER   = '0xf8b2c637A68cF6A17b1DF9F8992EeBeFf63d2dFf';

// Dolomite에서 USDC 마켓 ID (확인 필요: Dolomite 대시보드 또는 Etherscan에서 확인)
const USDC_MARKET_ID = 2;

// 최소 클레임 금액 (이 이하면 스킵 - 가스비 낭비 방지)
const MIN_WLFI_WEI = ethers.parseEther('1'); // 1 WLFI 이상일 때만 실행

// ─── ABI ───────────────────────────────────────────────────────────────────

const MERKL_ABI = [
  'function claim(address[] users, address[] tokens, uint256[] amounts, bytes32[][] proofs)'
];

const ERC20_ABI = [
  'function balanceOf(address) view returns (uint256)',
  'function approve(address spender, uint256 amount) returns (bool)',
];

const UNISWAP_ABI = [
  'function exactInputSingle((address tokenIn, address tokenOut, uint24 fee, address recipient, uint256 amountIn, uint256 amountOutMinimum, uint160 sqrtPriceLimitX96)) returns (uint256 amountOut)'
];

const DOLOMITE_ABI = [
  'function depositWei(uint256 _accountIndex, uint256 _marketId, uint256 _amountWei)'
];

// ─── 메인 ──────────────────────────────────────────────────────────────────

async function main() {
  if (!process.env.PRIVATE_KEY) {
    throw new Error('.env 파일에 PRIVATE_KEY가 없습니다');
  }

  const provider = new ethers.JsonRpcProvider(RPC_URL);
  const wallet   = new ethers.Wallet(process.env.PRIVATE_KEY, provider);

  console.log('지갑:', WALLET);
  console.log('');

  // ── 1. Merkl 보상 확인 ────────────────────────────────────────────────
  console.log('[1/4] Merkl 보상 확인 중...');
  const { data } = await axios.get(
    `https://api.merkl.xyz/v4/users/${WALLET}/rewards?chainId=1`
  );

  const claimData = data?.claim;
  if (!claimData || !claimData.tokens?.length) {
    console.log('클레임할 보상이 없습니다.');
    console.log('API 응답:', JSON.stringify(data, null, 2));
    return;
  }

  const wlfiIndex = claimData.tokens
    .map(t => t.toLowerCase())
    .indexOf(WLFI.toLowerCase());

  if (wlfiIndex === -1) {
    console.log('WLFI 보상 없음. 보유 토큰:', claimData.tokens);
    return;
  }

  const claimAmount = BigInt(claimData.amounts[wlfiIndex]);
  console.log(`클레임 가능: ${ethers.formatEther(claimAmount)} WLFI`);

  if (claimAmount < MIN_WLFI_WEI) {
    console.log(`최소 기준(${ethers.formatEther(MIN_WLFI_WEI)} WLFI) 미달, 스킵.`);
    return;
  }

  // ── 2. WLFI 클레임 ────────────────────────────────────────────────────
  console.log('');
  console.log('[2/4] WLFI 클레임 중...');
  const distributor = new ethers.Contract(MERKL_DISTRIBUTOR, MERKL_ABI, wallet);
  const claimTx = await distributor.claim(
    [WALLET],
    [WLFI],
    [claimData.amounts[wlfiIndex]],
    [claimData.proofs[wlfiIndex]]
  );
  await claimTx.wait();
  console.log('클레임 완료:', claimTx.hash);

  // ── 3. WLFI → USDC 스왑 (Uniswap v3) ─────────────────────────────────
  console.log('');
  console.log('[3/4] WLFI → USDC 스왑 중...');
  const wlfiContract = new ethers.Contract(WLFI, ERC20_ABI, wallet);
  const wlfiBalance  = await wlfiContract.balanceOf(WALLET);
  console.log(`스왑할 WLFI: ${ethers.formatEther(wlfiBalance)}`);

  await (await wlfiContract.approve(UNISWAP_ROUTER, wlfiBalance)).wait();

  const router = new ethers.Contract(UNISWAP_ROUTER, UNISWAP_ABI, wallet);
  const swapTx = await router.exactInputSingle({
    tokenIn:             WLFI,
    tokenOut:            USDC,
    fee:                 10000,  // 1% 풀 (신규 토큰 기본값)
    recipient:           WALLET,
    amountIn:            wlfiBalance,
    amountOutMinimum:    0,      // TODO: 슬리피지 보호 추가 권장
    sqrtPriceLimitX96:   0
  });
  await swapTx.wait();
  console.log('스왑 완료:', swapTx.hash);

  // ── 4. Dolomite 리페이 ────────────────────────────────────────────────
  console.log('');
  console.log('[4/4] Dolomite USDC 리페이 중...');
  const usdcContract = new ethers.Contract(USDC, ERC20_ABI, wallet);
  const usdcBalance  = await usdcContract.balanceOf(WALLET);
  console.log(`리페이할 USDC: ${ethers.formatUnits(usdcBalance, 6)}`);

  await (await usdcContract.approve(DOLOMITE_ROUTER, usdcBalance)).wait();

  const dolomite = new ethers.Contract(DOLOMITE_ROUTER, DOLOMITE_ABI, wallet);
  const repayTx  = await dolomite.depositWei(0, USDC_MARKET_ID, usdcBalance);
  await repayTx.wait();
  console.log('리페이 완료:', repayTx.hash);

  console.log('');
  console.log('모든 작업 완료!');
}

main().catch(e => {
  console.error('에러:', e.message);
  process.exit(1);
});
