// Simulates the Apify pay-per-event platform as documented:
//  - each item written to the DEFAULT dataset is charged once (synthetic apify-default-dataset-item)
//  - a run has a max total charge; writes beyond it are dropped, then the run is aborted
//  - Actor.charge() does NOT exist here: any call to it makes a test fail (it would be a double-billing path)
export class RunAborted extends Error {}
export function fakePlatform({ input, price = 0.002, maxTotalChargeUsd = Infinity, failAfterPushCalls = Infinity } = {}) {
  const st = { dataset: [], kv: {}, chargedUsd: 0, pushCalls: 0, aborted: false, namedDatasetWrites: 0 };
  const Actor = {
    async getInput() { return input; },
    async pushData(data, eventName) {
      if (eventName !== undefined) throw new Error('custom event used: double-billing risk');
      if (st.aborted) throw new RunAborted('run already aborted');
      st.pushCalls++;
      if (st.pushCalls > failAfterPushCalls) throw new Error('simulated platform error');
      for (const item of Array.isArray(data) ? data : [data]) {
        if (st.chargedUsd + price > maxTotalChargeUsd + 1e-9) { st.aborted = true; throw new RunAborted('max total charge reached'); }
        st.dataset.push(item); st.chargedUsd += price;
      }
    },
    async setValue(k, v) { st.kv[k] = v; },
    async getValue(k) { return st.kv[k]; },
  };
  return { Actor, st };
}
