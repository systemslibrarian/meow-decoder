/**
 * __mocks__/react-native-svg.ts
 *
 * Jest mock for react-native-svg.
 * Replaces all SVG primitives with plain React Native View/Text stubs so that
 * tests can render components that import react-native-svg without errors.
 */

import React from 'react';
import { View, Text } from 'react-native';

const Svg = ({ children, ...props }: React.PropsWithChildren<object>) =>
  React.createElement(View, props as object, children);

const Circle = (props: object) => React.createElement(View, props);
const Ellipse = (props: object) => React.createElement(View, props);
const Line = (props: object) => React.createElement(View, props);
const G = ({ children, ...props }: React.PropsWithChildren<object>) =>
  React.createElement(View, props as object, children);
const Path = (props: object) => React.createElement(View, props);
const Rect = (props: object) => React.createElement(View, props);
const Text_ = ({ children, ...props }: React.PropsWithChildren<object>) =>
  React.createElement(Text, props as object, children);
const Defs = ({ children, ...props }: React.PropsWithChildren<object>) =>
  React.createElement(View, props as object, children);
const LinearGradient = ({ children, ...props }: React.PropsWithChildren<object>) =>
  React.createElement(View, props as object, children);
const Stop = (props: object) => React.createElement(View, props);

// Animated variants — same stubs are fine for test rendering
const AnimatedCircle = Circle;
const AnimatedLine = Line;
const AnimatedEllipse = Ellipse;
const AnimatedPath = Path;

export default Svg;
export {
  Svg,
  Circle,
  Ellipse,
  Line,
  G,
  Path,
  Rect,
  Text_ as SvgText,
  Defs,
  LinearGradient,
  Stop,
  AnimatedCircle,
  AnimatedLine,
  AnimatedEllipse,
  AnimatedPath,
};
