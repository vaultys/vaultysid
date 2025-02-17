import { hash, fromHex } from "./crypto";
const squareSize = 10;
const boardTopx = 0;
const boardTopy = 0;

const createFrom256 = (hex: string) => hex.match(/.{1,4}/g)?.map((line) => parseInt(line, 16).toString(2).padStart(16, "0")) || [];
const createFromFingerprint = (fp: string) => createFrom256(hash("sha256", fromHex(fp.replaceAll(" ", ""))).toString("hex"));

const nextstep = (bin: string[], memo: number[][]) => {
  const output = [];
  for (let i = 0; i < 16; i++) {
    let line = "";
    for (let j = 0; j < 16; j++) {
      let count = 0;
      for (let k = i - 1; k < i + 2; k++) {
        for (let l = j - 1; l < j + 2; l++) {
          if (k > -1 && k < 16 && l > -1 && l < 16) {
            if ((k != i || l != j) && bin[k][l] == "1") count++;
          }
        }
      }
      let live = false;
      if (count == 3) live = true;
      else if (count == 2 && bin[i][j] == "1") live = true;
      line += live ? "1" : "O";
      if (memo && live) {
        memo[i][j]++;
      }
    }
    output.push(line);
  }
  return output;
};

const run = (hex: string, max: number) => {
  const result = createFrom256(hex)?.map((line) =>
    line.split("").map((c) => parseInt(c)),
  );
  let step = createFrom256(hex);
  for (let a = 0; a < max; a++) {
    step = nextstep(step, result);
  }
  return result;
};

const renderStep = (context: CanvasRenderingContext2D, step: number[][]) => {
  for (let i = 0; i < 16; i++) {
    for (let j = 0; j < 16; j++) {
      context.fillStyle = step[i][j] == 1 ? "black" : "white";
      let xOffset = boardTopx + j * squareSize;
      let yOffset = boardTopy + i * squareSize;
      context.fillRect(xOffset, yOffset, squareSize, squareSize);
      context.fillRect(150 - xOffset, yOffset, squareSize, squareSize);
      context.fillRect(xOffset, 150 - yOffset, squareSize, squareSize);
      context.fillRect(150 - xOffset, 150 - yOffset, squareSize, squareSize);
    }
  }
};

const heatMapColorforValue = (value: number, offset = 1) => {
  var h = (1.0 - value) * 240 + offset;
  //return `rgba(0,0,0,${value})`
  return "hsl(" + h + ", 100%, 50%)";
};

const renderMemo = (data: number[][], mapcolors = 2, context: CanvasRenderingContext2D) => {
  let min = 1000;
  let max = 0;
  const memo = JSON.parse(JSON.stringify(data));
  for (let i = 0; i < 8; i++) {
    for (let j = 0; j < 8; j++) {
      memo[i][j] =
        memo[15 - i][j] =
        memo[i][15 - j] =
        memo[15 - i][15 - j] =
          memo[i][j] + memo[15 - i][j] + memo[i][15 - j] + memo[15 - i][15 - j];
      const val = memo[i][j];
      if (val < min) min = val;
      if (val > max) max = val;
    }
  }
  for (let i = 0; i < 16; i++) {
    for (let j = 0; j < 16; j++) {
      context.fillStyle = heatMapColorforValue(
        Math.floor(((memo[i][j] - min) * mapcolors) / max) / mapcolors,
        max * max,
      );
      let xOffset = boardTopx + j * squareSize;
      let yOffset = boardTopy + i * squareSize;
      context.fillRect(xOffset, yOffset, squareSize, squareSize);
    }
  }
};

export default {
  renderFingerprint: (fp: string, canvas: HTMLCanvasElement, steps = 32) => {
    let step = createFromFingerprint(fp.replaceAll(" ", ""));
    let memo = step?.map((line) => line.split("").map((c) => parseInt(c)));
    const context = canvas.getContext("2d");
    if(!context || !memo ) return;
    for (let t = 0; t < steps; t++) {
      step = nextstep(step, memo);
    }
    renderMemo(memo, 3, context);
    return canvas;
  },

  animateFingerprint: async (fp: string, canvas: HTMLCanvasElement, steps = 32, speed = 500) => {
    let step = createFromFingerprint(fp.replaceAll(" ", ""));
    let memo = step?.map((line) => line.split("").map((c) => parseInt(c)));
    const context = canvas.getContext("2d");
    if(!context || !memo) return;
    for (let t = 0; t < steps; t++) {
      step = nextstep(step, memo);
      renderMemo(memo, 3, context);
      await new Promise((resolve) => setTimeout(resolve, speed));
    }
    renderMemo(memo, 3, context);
    return canvas;
  },
};
