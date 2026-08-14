type LineTitleProps = {
  lines: string[];
};

export function LineTitle({ lines }: LineTitleProps) {
  return (
    <>
      {lines.map((line, index) => (
        <span className="title-line" key={line}>
          {line}
          {index < lines.length - 1 ? <br /> : null}
        </span>
      ))}
    </>
  );
}
