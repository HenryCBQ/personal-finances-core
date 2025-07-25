import { ExceptionFilter, Catch, ArgumentsHost, HttpException, HttpStatus, Logger } from '@nestjs/common';
import { HttpAdapterHost } from '@nestjs/core';

@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
    private readonly logger = new Logger(AllExceptionsFilter.name);

    constructor(private readonly httpAdapterHost: HttpAdapterHost) {}

    catch(exception: unknown, host: ArgumentsHost): void {
        const { httpAdapter } = this.httpAdapterHost;
        const ctx = host.switchToHttp();
        const httpStatus = exception instanceof HttpException 
            ? exception.getStatus() 
            : HttpStatus.INTERNAL_SERVER_ERROR;
        const message = exception instanceof HttpException 
            ? exception.getResponse() 
            : 'Internal server error. View server logs';

        this.logger.error(`Exception: ${exception}`, (exception as Error).message);

        const responseBody = {
            statusCode: httpStatus,
            timestamp: new Date().toISOString(),
            path: httpAdapter.getRequestUrl(ctx.getRequest()),
            message: message,
        };
        httpAdapter.reply(ctx.getResponse(), responseBody, httpStatus);
    }
}