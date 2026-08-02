
import { getUsdKesRateMeta, applySellMargin } from '../services/currency.service.js';


export const getRate = async (req, res) => {
  try {
    const { rate: midRate, source, cached } = await getUsdKesRateMeta();
    const sellRate = applySellMargin(midRate);

    return res.json({
      success: true,
      usdKes:  Math.round(sellRate * 100) / 100,
      source,
      cached,
    });
  } catch (err) {
    
    // currency.service.js is designed to never throw (it always resolves to
    // at least the static fallback), so this branch should be unreachable
    // in practice — kept only as a last-resort guard.
    return res.status(500).json({ success: false, message: 'Unable to fetch exchange rate' });
  }
};