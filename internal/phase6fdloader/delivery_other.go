//go:build !linux

package phase6fdloader

import "context"

type DeliveryChannel struct{}

func OpenDeliveryChannel(context.Context) (*DeliveryChannel, StartupBinding, error) {
	return nil, StartupBinding{}, ErrInvalid
}
func (*DeliveryChannel) Close()                                         {}
func (*DeliveryChannel) ReadReply(context.Context, int) ([]byte, error) { return nil, ErrInvalid }
func ReadStartupBinding(context.Context) (StartupBinding, error)        { return StartupBinding{}, ErrInvalid }
func WriteOutput(context.Context, []byte, int) error                    { return ErrInvalid }
