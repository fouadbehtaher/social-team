import React from "react";
import {registerRoot, Composition, AbsoluteFill, useCurrentFrame, interpolate} from "remotion";
const T = ({text, head, banner}) => {
  const f = useCurrentFrame(); const o = interpolate(f, [0, 20], [0, 1], {extrapolateRight: "clamp"});
  return (<AbsoluteFill style={{background: "#0e1424", color: "white", fontFamily: "Noto Kufi Arabic, DejaVu Sans, sans-serif", padding: 80, justifyContent: "center"}}>
    {banner ? <div style={{background: "#ffd54f", color: "#000", padding: 16, fontSize: 36, fontWeight: 700, marginBottom: 60}}>{banner}</div> : null}
    <div dir="auto" style={{fontSize: 80, fontWeight: 700, opacity: o, unicodeBidi: "plaintext"}}>{head}</div>
    <div dir="auto" style={{fontSize: 44, marginTop: 40, opacity: o, color: "#bcc6dc", unicodeBidi: "plaintext"}}>{text}</div>
  </AbsoluteFill>);
};
registerRoot(() => <Composition id="Clip" component={T} durationInFrames={60} fps={30} width={1080} height={1920}
  defaultProps={{head: "عنصر تجريبي: ليس منشورًا حقيقيًا", text: "نص ثابت لفحص مسار الفيديو. لا يتحدث عن أي ثغرة أو مصدر حقيقي."}} />);
