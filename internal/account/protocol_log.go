package account

import (
	"context"
	"io"
	"log/slog"
)

type protocolLogHandler struct{ base slog.Handler }

func ProtocolLogHandler(writer io.Writer) slog.Handler {
	return protocolLogHandler{slog.NewJSONHandler(writer, nil)}
}
func (handler protocolLogHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= slog.LevelWarn
}
func (handler protocolLogHandler) Handle(ctx context.Context, record slog.Record) error {
	return handler.base.Handle(ctx, slog.NewRecord(record.Time, record.Level, "oidc_protocol_event", 0))
}
func (handler protocolLogHandler) WithAttrs([]slog.Attr) slog.Handler { return handler }
func (handler protocolLogHandler) WithGroup(string) slog.Handler      { return handler }
