/**
 * Mock: react-native-worklets-core
 *
 * The Cat Mode frame-processor sampler (useCatBlinkSampler) calls
 * Worklets.createRunOnJS to hop a brightness sample from the worklet thread back
 * to JS. In tests there is no worklet thread, so createRunOnJS just returns the
 * function unchanged (synchronous passthrough).
 */
export const Worklets = {
  createRunOnJS: <C extends (...args: never[]) => void>(fn: C): C => fn,
};
