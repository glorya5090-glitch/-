export interface SingleFlightGate {
  enter(): boolean;
  readonly locked: boolean;
  release(): void;
}

export function createSingleFlightGate(): SingleFlightGate {
  let locked = false;

  return {
    enter() {
      if (locked) {
        return false;
      }

      locked = true;
      return true;
    },
    get locked() {
      return locked;
    },
    release() {
      locked = false;
    },
  };
}
